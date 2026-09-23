package peer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/observability"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/tokenwatch"
)

// Borrower is the seam internal/auth borrows through. *Pool satisfies it;
// tests fake it.
type Borrower interface {
	// Borrow returns the first token any active peer yields and the socket
	// path it came from, or ("", "") when no peer produced one. Best-effort:
	// it never returns an error.
	Borrow(ctx context.Context) (token, source string)
}

var _ Borrower = (*Pool)(nil)

// ErrNoPeers is returned by Broadcast when the pool has no active member.
// It wraps ErrPeerUnreachable so callers that only care about "could not
// reach a peer" need one errors.Is.
var ErrNoPeers = fmt.Errorf("no active peer sockets: %w", ErrPeerUnreachable)

// EvictProbeInterval is how long an evicted member stays out of rotation
// before it is probed again. Eviction is a re-probe window, not a verdict —
// the same reasoning as auth.DenyProbeInterval. A forward whose TCP side
// stalled and then recovered keeps its inode, so without this it would stay
// dark until the process restarted.
const EvictProbeInterval = 5 * time.Minute

// Member is one resolved socket, as reported by Status.
type Member struct {
	Path      string    `json:"path"`
	LastSeen  time.Time `json:"last_seen"`
	Evicted   bool      `json:"evicted"`
	EvictedAt time.Time `json:"evicted_at,omitempty"`
}

// Status is the pool's externally visible state (GET /api/v1/status
// "peer_sockets", `dotvault status`).
type Status struct {
	Patterns []string `json:"patterns"`
	Members  []Member `json:"members"`
}

// identity is what tells a recreated socket from the same one: device and
// inode. Zero on platforms where the stat does not expose them.
type identity struct {
	dev uint64
	ino uint64
}

type member struct {
	path      string
	pattern   int // index into patterns, for tie-breaking
	id        identity
	lastSeen  time.Time
	evictedAt time.Time // zero when active
}

// Pool resolves a list of socket patterns into live peers, orders them
// most-recently-seen first, evicts the unreachable and readmits them when
// they come back. Every method is nil-receiver safe.
type Pool struct {
	patterns []string // expanded (~ resolved), original order
	raw      []string // as configured, for Status

	clock        func() time.Time
	fetchTimeout time.Duration
	postTimeout  time.Duration
	onChange     func()

	mu      sync.Mutex
	members map[string]*member
}

// Option configures a Pool.
type Option func(*Pool)

// WithClock overrides the wall clock (tests).
func WithClock(now func() time.Time) Option { return func(p *Pool) { p.clock = now } }

// WithOnChange registers a hook fired from Watch whenever a matching socket
// is created or written. The daemon wires its "re-borrow now" nudges here.
func WithOnChange(fn func()) Option { return func(p *Pool) { p.onChange = fn } }

// withFetchTimeout and withPostTimeout shorten the per-member bounds so a test
// can exercise the unreachable path without waiting out FetchTimeout or
// PostTimeout. They can only ever shorten: the transport applies its own bound
// too, and the earlier deadline wins.
func withFetchTimeout(d time.Duration) Option { return func(p *Pool) { p.fetchTimeout = d } }
func withPostTimeout(d time.Duration) Option  { return func(p *Pool) { p.postTimeout = d } }

func watchSupported() bool { return runtime.GOOS == "linux" }

// NewPool builds a pool over patterns (literal paths or final-segment globs,
// ~-relative allowed). Patterns that cannot be expanded are dropped with a
// debug log; an all-empty list yields a pool that never borrows.
func NewPool(patterns []string, opts ...Option) *Pool {
	p := &Pool{
		raw:          append([]string(nil), patterns...),
		clock:        func() time.Time { return time.Now().Round(0) },
		fetchTimeout: FetchTimeout,
		postTimeout:  PostTimeout,
		members:      make(map[string]*member),
	}
	for _, o := range opts {
		o(p)
	}
	for _, pat := range patterns {
		if pat == "" {
			continue
		}
		expanded, err := paths.ExpandHome(pat)
		if err != nil {
			slog.Debug("peer socket pattern unusable; skipping", "pattern", pat, "error", err)
			continue
		}
		p.patterns = append(p.patterns, expanded)
	}
	return p
}

// Patterns returns the expanded patterns in order.
func (p *Pool) Patterns() []string {
	if p == nil {
		return nil
	}
	return append([]string(nil), p.patterns...)
}

// resolveLocked globs every pattern, admits new matches, refreshes identity
// and readmits recreated or probe-expired members, and drops vanished ones.
// Caller holds p.mu.
func (p *Pool) resolveLocked(ctx context.Context) {
	now := p.clock()
	seen := make(map[string]bool)
	for i, pat := range p.patterns {
		matches, err := filepath.Glob(pat)
		if err != nil {
			slog.Debug("peer socket pattern is malformed; skipping", "pattern", pat, "error", err)
			continue
		}
		for _, path := range matches {
			if seen[path] {
				continue
			}
			fi, err := os.Stat(path)
			if err != nil || fi.Mode()&os.ModeSocket == 0 {
				continue // vanished between glob and stat, or not a socket
			}
			seen[path] = true
			id := statIdentity(fi)
			m, ok := p.members[path]
			if !ok {
				p.members[path] = &member{path: path, pattern: i, id: id, lastSeen: fi.ModTime()}
				observability.RecordPeerPool(ctx, "admitted")
				continue
			}
			if m.id != id {
				// Recreated: a new socket behind the same name. On a platform
				// with no inotify this is what a forward reconnecting looks
				// like, so it is readmission evidence in its own right.
				m.id = id
				if fi.ModTime().After(m.lastSeen) {
					m.lastSeen = fi.ModTime()
				}
				if !m.evictedAt.IsZero() {
					m.evictedAt = time.Time{}
					observability.RecordPeerPool(ctx, "readmitted")
				}
				continue
			}
			if !m.evictedAt.IsZero() && now.Sub(m.evictedAt) >= EvictProbeInterval {
				m.evictedAt = time.Time{}
				observability.RecordPeerPool(ctx, "readmitted")
			}
		}
	}
	// A member whose file has gone is dropped outright: there is nothing left
	// to probe, and a socket at that name later is a different peer anyway.
	for path := range p.members {
		if !seen[path] {
			delete(p.members, path)
		}
	}
}

// activeLocked returns the active members, ordered. Caller holds p.mu.
//
// It returns value copies rather than pointers deliberately: callers use the
// snapshot after releasing the lock, and resolveLocked refreshes a member's
// identity and lastSeen in place, so handing out pointers would be a data
// race. The copy is also what lets Borrow and Broadcast carry the identity
// they dialled into evict.
func (p *Pool) activeLocked() []member {
	out := make([]member, 0, len(p.members))
	for _, m := range p.members {
		if m.evictedAt.IsZero() {
			out = append(out, *m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].lastSeen.Equal(out[j].lastSeen) {
			return out[i].lastSeen.After(out[j].lastSeen)
		}
		if out[i].pattern != out[j].pattern {
			return out[i].pattern < out[j].pattern
		}
		return out[i].path < out[j].path
	})
	return out
}

// Resolve re-globs the patterns and returns the active members in borrow
// order.
func (p *Pool) Resolve() []Member {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resolveLocked(context.Background())
	act := p.activeLocked()
	out := make([]Member, len(act))
	for i, m := range act {
		out[i] = Member{Path: m.path, LastSeen: m.lastSeen}
	}
	return out
}

// evict takes path out of rotation after a transport failure. Idempotent.
//
// id is the identity the failing caller actually dialled, and a mismatch is a
// no-op: a fetch that hung for its whole timeout can outlive the socket it was
// dialling, and in that window a concurrent resolve may have readmitted (or
// freshly admitted) a *recreated* socket at the same name — exactly the
// reconnect the pool exists to follow. Keying eviction on the name alone would
// let that stale failure take the healthy replacement dark for a whole
// EvictProbeInterval, having already consumed the inotify event that would
// have brought it back. Note statIdentity is a stub on Windows, so the guard
// is inert there; that platform resolves no Unix peer sockets anyway.
func (p *Pool) evict(ctx context.Context, path string, id identity, cause error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m, ok := p.members[path]
	if !ok || !m.evictedAt.IsZero() {
		return
	}
	if m.id != id {
		slog.Debug("ignoring stale peer socket failure; socket was recreated meanwhile",
			"socket", path, "error", cause)
		return
	}
	m.evictedAt = p.clock()
	observability.RecordPeerPool(ctx, "evicted")
	slog.Debug("peer socket evicted from pool", "socket", path, "error", cause)
}

// Borrow implements Borrower: active members most-recently-seen first, the
// first token wins. A transport failure evicts the member; an HTTP non-200
// (the peer holds no token) does not — it is alive and merely waiting to
// authenticate itself, which is the common case for a peer that has just
// started.
func (p *Pool) Borrow(ctx context.Context) (string, string) {
	if p == nil {
		return "", ""
	}
	p.mu.Lock()
	p.resolveLocked(ctx)
	act := p.activeLocked()
	p.mu.Unlock()

	for _, m := range act {
		fctx, cancel := context.WithTimeout(ctx, p.fetchTimeout)
		token, err := fetchTokenDetailed(fctx, m.path)
		cancel()
		if err != nil {
			p.evict(ctx, m.path, m.id, err)
			continue
		}
		if token != "" {
			return token, m.path
		}
	}
	return "", ""
}

// Broadcast posts form to every active member concurrently. Any 200 → nil.
// Any 4xx → that *StatusError, since bad input is bad everywhere and the
// caller must hear it even when another peer accepted. No active member →
// ErrNoPeers. Everything failed → a joined error wrapping ErrPeerUnreachable.
// Transport failures evict, exactly as in Borrow.
func (p *Pool) Broadcast(ctx context.Context, apiPath string, form url.Values) error {
	if p == nil {
		return ErrNoPeers
	}
	p.mu.Lock()
	p.resolveLocked(ctx)
	act := p.activeLocked()
	p.mu.Unlock()
	if len(act) == 0 {
		return ErrNoPeers
	}

	type result struct {
		path string
		id   identity
		err  error
	}
	// A pool holds a handful of sockets, so the member count is the bound.
	results := make(chan result, len(act))
	for _, m := range act {
		go func(path string, id identity) {
			pctx, cancel := context.WithTimeout(ctx, p.postTimeout)
			defer cancel()
			results <- result{path, id, PostForm(pctx, path, apiPath, form)}
		}(m.path, m.id)
	}

	var (
		accepted bool
		rejected *StatusError
		failures []error
	)
	for range act {
		r := <-results
		switch {
		case r.err == nil:
			accepted = true
		case errors.Is(r.err, ErrPeerUnreachable):
			p.evict(ctx, r.path, r.id, r.err)
			failures = append(failures, fmt.Errorf("%s: %w", r.path, r.err))
		default:
			var se *StatusError
			if errors.As(r.err, &se) && se.Status >= 400 && se.Status < 500 {
				if rejected == nil {
					rejected = se
				}
			}
			failures = append(failures, fmt.Errorf("%s: %w", r.path, r.err))
		}
	}
	if rejected != nil {
		return rejected
	}
	if accepted {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrPeerUnreachable, errors.Join(failures...))
}

// Watch blocks until ctx is done, watching every pattern's parent directory
// for matching sockets being created or written. On an event the member's
// lastSeen is bumped, its eviction cleared, and the OnChange hook fired.
// A no-op on platforms without inotify (the on-demand re-resolve covers
// them); an unwatchable directory degrades to that too.
func (p *Pool) Watch(ctx context.Context) error {
	if p == nil || len(p.patterns) == 0 {
		return nil
	}
	dirs := make(map[string][]string) // dir -> patterns
	for _, pat := range p.patterns {
		dirs[filepath.Dir(pat)] = append(dirs[filepath.Dir(pat)], filepath.Base(pat))
	}
	var wg sync.WaitGroup
	for dir, names := range dirs {
		dir, names := dir, names
		match := func(name string) bool {
			for _, n := range names {
				if ok, _ := filepath.Match(n, name); ok {
					return true
				}
			}
			return false
		}
		w, err := tokenwatch.NewMatch(dir, match, func(name string) {
			// Only nudge when the event actually moved a member: a
			// non-socket file created under a matching name would
			// otherwise wake the daemon for nothing.
			if p.noteSeen(ctx, filepath.Join(dir, name)) && p.onChange != nil {
				p.onChange()
			}
		})
		if err != nil {
			slog.Debug("peer socket directory not watchable; relying on re-resolve", "dir", dir, "error", err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer w.Close()
			if err := w.Run(ctx); err != nil && ctx.Err() == nil {
				slog.Debug("peer socket watcher stopped", "dir", dir, "error", err)
			}
		}()
	}
	wg.Wait()
	return nil
}

// noteSeen records a watch event for path: admit or refresh the member with
// lastSeen = now and clear any eviction. It reports whether it did either, so
// the caller can tell a real socket appearing from an event it discarded.
func (p *Pool) noteSeen(ctx context.Context, path string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clock()
	fi, err := os.Stat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return false
	}
	m, ok := p.members[path]
	if !ok {
		idx := 0
		for i, pat := range p.patterns {
			if ok, _ := filepath.Match(pat, path); ok {
				idx = i
				break
			}
		}
		p.members[path] = &member{path: path, pattern: idx, id: statIdentity(fi), lastSeen: now}
		observability.RecordPeerPool(ctx, "admitted")
		return true
	}
	m.id = statIdentity(fi)
	m.lastSeen = now
	if !m.evictedAt.IsZero() {
		m.evictedAt = time.Time{}
		observability.RecordPeerPool(ctx, "readmitted")
	}
	return true
}

// Status reports the pool for diagnostics; evicted members are included,
// since "two sockets, one evicted" is the answer a human needs and an
// active-only view would show nothing at all.
func (p *Pool) Status() Status {
	if p == nil {
		return Status{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resolveLocked(context.Background())
	out := Status{Patterns: append([]string(nil), p.raw...)}
	for _, m := range p.members {
		out.Members = append(out.Members, Member{
			Path: m.path, LastSeen: m.lastSeen,
			Evicted: !m.evictedAt.IsZero(), EvictedAt: m.evictedAt,
		})
	}
	sort.Slice(out.Members, func(i, j int) bool { return out.Members[i].Path < out.Members[j].Path })
	return out
}
