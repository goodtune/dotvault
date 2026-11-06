package peer

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/events"
	"github.com/goodtune/dotvault/internal/kvpath"
)

// EventIdleTimeout is how long StreamEvents waits for any line — an event or
// the peer's heartbeat comment — before treating the stream as dead. A
// forwarded socket whose SSH session went away can leave the local half of
// the connection open with nothing behind it; without a bound the subscriber
// would wait on it forever and never reconnect. It sits well above the
// peer's 25s heartbeat (internal/web eventsHeartbeat) so a slow tunnel is not
// mistaken for a dead one.
const EventIdleTimeout = 75 * time.Second

// eventLineLimit caps one SSE line. An event is a small JSON object; the cap
// guards against a misbehaving peer streaming an unbounded line.
const eventLineLimit = 1 << 16

// StreamEvents subscribes to a peer's GET /api/v1/events and calls fn for
// every secret-write notice until the stream ends, ctx is cancelled, or the
// stream goes idle for EventIdleTimeout. It always returns a non-nil error
// describing why the stream ended: ErrPeerUnreachable (wrapped) when the peer
// could not be contacted, a *StatusError when it answered non-200 (a 404
// means a peer that predates the endpoint), or the read error otherwise.
func StreamEvents(ctx context.Context, socketPath string, fn func(events.Event)) error {
	client, _, err := Client(socketPath)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPeerUnreachable, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The idle watchdog cancels the request, which unblocks the body read.
	idle := time.AfterFunc(EventIdleTimeout, cancel)
	defer idle.Stop()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/api/v1/events", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPeerUnreachable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusErrorFrom(resp)
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 4096), eventLineLimit)
	var name string
	var data strings.Builder
	for sc.Scan() {
		idle.Reset(EventIdleTimeout)
		line := sc.Text()
		switch {
		case line == "":
			// A blank line ends one event.
			if name == "kv-write" && data.Len() > 0 {
				var e events.Event
				if err := json.Unmarshal([]byte(data.String()), &e); err == nil && validEvent(e) {
					fn(e)
				} else {
					slog.Debug("peer events: malformed event; ignoring", "socket", socketPath)
				}
			}
			name = ""
			data.Reset()
		case strings.HasPrefix(line, ":"):
			// Comment: the peer's heartbeat. Its only job is the Reset above.
		case strings.HasPrefix(line, "event:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			// Per the SSE spec, successive data lines are joined with a
			// newline; one leading space after the colon is not part of the
			// value.
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			if data.Len() > eventLineLimit {
				return errors.New("peer event too large")
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return io.EOF
}

// maxEventKeyLen bounds an event key received from a peer. A real key is an
// enrolment key (a name, or group/name); the bound keeps a hostile peer from
// filling logs and the deduplication table with arbitrary strings.
const maxEventKeyLen = 256

// validEvent reports whether an event from a peer is well formed: a
// canonical relative KV path no longer than maxEventKeyLen, and a real KVv2
// version. Anything else is dropped before it is logged or acted on.
func validEvent(e events.Event) bool {
	if e.Version <= 0 || e.Key == "" || len(e.Key) > maxEventKeyLen {
		return false
	}
	// Keys reach consumers that print them or build names from them; a
	// control character in one is never a real enrolment key.
	for _, r := range e.Key {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	clean, err := kvpath.Clean(e.Key)
	return err == nil && clean == e.Key
}

// knownSources are the writers a daemon names in Event.Source. Anything else
// from a peer is dropped to "" rather than passed on, so a hostile upstream
// cannot label a notice as, say, a rotation for every host downstream.
var knownSources = map[string]bool{"refresh": true, "watch": true}

// sanitise rewrites the parts of a peer's notice this host cannot vouch for:
// an unknown Source becomes "", and Time becomes the moment this host heard
// it. Key and Version are already validated, and are what consumers act on.
func sanitise(e events.Event) events.Event {
	if !knownSources[e.Source] {
		e.Source = ""
	}
	e.Time = time.Now().UTC()
	return e
}

// PostSync asks a peer daemon to run a sync cycle now, through its
// CSRF-protected POST /api/v1/sync: it fetches a one-time token from
// GET /api/v1/csrf and spends it on the POST. Errors are typed as for
// PostForm.
func PostSync(ctx context.Context, socketPath string) error {
	client, _, err := Client(socketPath)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPeerUnreachable, err)
	}
	ctx, cancel := context.WithTimeout(ctx, PostTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/api/v1/csrf", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPeerUnreachable, err)
	}
	var tok struct {
		Token string `json:"token"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(resp.Body, peerResponseBodyLimit)).Decode(&tok)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &StatusError{Status: resp.StatusCode}
	}
	if decodeErr != nil || tok.Token == "" {
		return errors.New("peer issued no CSRF token")
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/api/v1/sync", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-CSRF-Token", tok.Token)
	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPeerUnreachable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusErrorFrom(resp)
	}
	return nil
}

// Relay timing. relayReconcileInterval is how often the relay re-globs the
// pool for sockets that appeared or vanished; Kick shortcuts it where the
// pool's watcher can see the change. The backoff applies per socket between
// stream attempts, and a peer answering 404 (one that predates the events
// endpoint) goes straight to the cap rather than being asked every second.
const (
	relayReconcileInterval = 30 * time.Second
	relayMinBackoff        = time.Second
	relayMaxBackoff        = 5 * time.Minute
	// relayHealthyStream is how long a stream must have stayed up for its
	// end to count as a disconnect rather than a failure, resetting backoff.
	relayHealthyStream = 30 * time.Second
	// relaySyncSpacing is the minimum gap between two syncs the relay asks
	// of the same peer. A peer cannot make this host flood the others: a
	// burst of notices collapses into at most one sync in flight and one
	// queued behind it per peer, at most one per spacing.
	relaySyncSpacing = 5 * time.Second
)

// Relay listens to every live member of a Pool for secret-write notices and
// hands each new one to its onEvent callback. With WithFanOut it also asks
// every *other* member to sync — the daemon's mode; the client facade's
// subscriptions only listen.
//
// The second half exists because the desktops a host borrows from do not know
// about one another. A token rotated on one desktop reaches the others only at
// their next sync poll — and on Vault Community, which has no event API, that
// is the whole of the delay, during which they hold an access token the
// provider has already invalidated. A host connected to several desktops is
// the one place that can see them all, so it passes the word along. The
// member the notice came from is skipped; it wrote the secret.
//
// A notice is acted on once per (key, version) (events.Seen), so the same
// write reported by two desktops, or replayed after a reconnect, costs nothing
// extra. A peer told to sync does not emit a notice of its own — syncing reads
// Vault and writes files, it does not write Vault — so relays cannot loop.
// Syncs asked of each peer are single-flight and spaced (relaySyncSpacing),
// so a misbehaving peer streaming notices cannot turn this host into an
// amplifier against the others.
//
// Membership follows Pool.Resolve, which lists only *active* members: a
// socket the token borrow evicted (a transport failure) loses its stream
// until the pool readmits it. That is the pool's single view of which peers
// are reachable, and a stream to an unreachable peer would fail anyway.
type Relay struct {
	pool    *Pool
	onEvent func(events.Event)
	seen    *events.Seen
	fanOut  bool

	// Seams for tests; production uses StreamEvents, PostSync and the
	// constants above.
	stream     func(ctx context.Context, path string, fn func(events.Event)) error
	postSync   func(ctx context.Context, path string) error
	interval   time.Duration
	minBackoff time.Duration
	maxBackoff time.Duration
	spacing    time.Duration

	kick chan struct{}

	mu      sync.Mutex
	runCtx  context.Context
	streams map[string]*relayStream
	syncs   map[string]*relaySync
	wg      sync.WaitGroup
}

// relayStream is one member's subscription.
type relayStream struct {
	cancel   context.CancelFunc
	wake     chan struct{} // interrupts a backoff wait
	lastSeen time.Time     // the member's LastSeen when last reconciled
}

// relaySync is the single-flight state of syncs asked of one peer.
type relaySync struct {
	again bool // another notice arrived while a sync was in flight
}

// RelayOption configures a Relay.
type RelayOption func(*Relay)

// WithFanOut makes the relay ask every member other than a notice's source
// to sync. Without it the relay only listens.
func WithFanOut() RelayOption { return func(r *Relay) { r.fanOut = true } }

// WithSeen shares a deduplication table with the caller. The daemon passes
// the table it also records its own writes in, so a notice of its own that
// comes back round a mesh of peers is recognised and not acted on twice.
func WithSeen(s *events.Seen) RelayOption { return func(r *Relay) { r.seen = s } }

// NewRelay builds a relay over pool. onEvent is called once for every new,
// well-formed notice, possibly from several goroutines at once (one per
// member stream); it must not block for long, since the stream it was called
// from does not read while it runs.
func NewRelay(pool *Pool, onEvent func(events.Event), opts ...RelayOption) *Relay {
	r := &Relay{
		pool:       pool,
		onEvent:    onEvent,
		seen:       events.NewSeen(),
		stream:     StreamEvents,
		postSync:   PostSync,
		interval:   relayReconcileInterval,
		minBackoff: relayMinBackoff,
		maxBackoff: relayMaxBackoff,
		spacing:    relaySyncSpacing,
		kick:       make(chan struct{}, 1),
		streams:    make(map[string]*relayStream),
		syncs:      make(map[string]*relaySync),
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Kick asks the relay to re-glob the pool now and retry any stream that is
// backing off: the pool's watcher calls it when a socket is created or
// replaced, which is what a forward reconnecting looks like. Safe on a nil
// Relay.
func (r *Relay) Kick() {
	if r == nil {
		return
	}
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// Run subscribes to the pool's members until ctx is cancelled, and waits for
// every stream and every sync it started to stop before returning.
func (r *Relay) Run(ctx context.Context) {
	if r == nil || r.pool == nil || len(r.pool.Patterns()) == 0 {
		return
	}
	r.mu.Lock()
	r.runCtx = ctx
	r.mu.Unlock()
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	defer r.wg.Wait()
	wakeAll := false
	for {
		r.reconcile(ctx, wakeAll)
		select {
		case <-ctx.Done():
			r.mu.Lock()
			for path, st := range r.streams {
				st.cancel()
				delete(r.streams, path)
			}
			r.mu.Unlock()
			return
		case <-ticker.C:
			wakeAll = false
		case <-r.kick:
			wakeAll = true
		}
	}
}

// reconcile starts a stream for every member without one, stops the streams
// of members that are gone, and wakes a backing-off stream whose socket has
// been recreated (its LastSeen moved on) — or every stream, when wakeAll.
func (r *Relay) reconcile(ctx context.Context, wakeAll bool) {
	live := make(map[string]time.Time)
	for _, m := range r.pool.Resolve() {
		live[m.Path] = m.LastSeen
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for path, st := range r.streams {
		if _, ok := live[path]; !ok {
			st.cancel()
			delete(r.streams, path)
		}
	}
	for path, seen := range live {
		if st, ok := r.streams[path]; ok {
			if wakeAll || seen.After(st.lastSeen) {
				st.lastSeen = seen
				select {
				case st.wake <- struct{}{}:
				default:
				}
			}
			continue
		}
		sctx, cancel := context.WithCancel(ctx)
		st := &relayStream{cancel: cancel, wake: make(chan struct{}, 1), lastSeen: seen}
		r.streams[path] = st
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.streamLoop(sctx, path, st.wake)
		}()
	}
}

func (r *Relay) streamLoop(ctx context.Context, path string, wake <-chan struct{}) {
	backoff := r.minBackoff
	for {
		started := time.Now()
		err := r.stream(ctx, path, func(e events.Event) { r.handle(path, e) })
		if ctx.Err() != nil {
			return
		}
		var se *StatusError
		switch {
		case errors.As(err, &se) && se.Status == http.StatusNotFound:
			slog.Debug("peer events: peer has no events endpoint; retrying later", "socket", path)
			backoff = r.maxBackoff
		case time.Since(started) >= relayHealthyStream:
			slog.Debug("peer events: stream ended; reconnecting", "socket", path, "error", err)
			backoff = r.minBackoff
		default:
			slog.Debug("peer events: stream failed; backing off", "socket", path, "backoff", backoff, "error", err)
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-wake:
			// The socket was recreated: whatever the last attempt met is
			// gone, so retry now and start the backoff over.
			timer.Stop()
			backoff = r.minBackoff
			continue
		case <-timer.C:
		}
		backoff *= 2
		if backoff > r.maxBackoff {
			backoff = r.maxBackoff
		}
	}
}

// handle acts on one notice received from source.
func (r *Relay) handle(source string, e events.Event) {
	if !validEvent(e) {
		slog.Debug("peer events: malformed notice; ignoring", "socket", source)
		return
	}
	if !r.seen.Admit(e) {
		slog.Debug("peer events: duplicate notice; ignoring", "key", e.Key, "version", e.Version, "socket", source)
		return
	}
	e = sanitise(e)
	// INFO in the daemon, where it explains a sync; DEBUG in a listen-only
	// relay, which runs inside someone else's program and must not write a
	// line to its stderr for every notice.
	level := slog.LevelDebug
	if r.fanOut {
		level = slog.LevelInfo
	}
	slog.Log(context.Background(), level, "peer events: secret changed on a peer", "key", e.Key, "version", e.Version, "socket", source)
	if r.onEvent != nil {
		r.onEvent(e)
	}
	if !r.fanOut {
		return
	}
	for _, m := range r.pool.Resolve() {
		if m.Path != source {
			r.requestSync(m.Path)
		}
	}
}

// requestSync asks the peer at path to sync, single-flight: while one request
// is in flight (or inside its spacing window) further requests collapse into
// one more run afterwards. A sync is a full re-read, so asking twice while
// the first is pending adds nothing but load.
func (r *Relay) requestSync(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.runCtx == nil || r.runCtx.Err() != nil {
		return
	}
	if st, ok := r.syncs[path]; ok {
		st.again = true
		return
	}
	st := &relaySync{}
	r.syncs[path] = st
	ctx := r.runCtx
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			r.syncOnce(ctx, path)
			timer := time.NewTimer(r.spacing)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
			r.mu.Lock()
			if st.again && ctx.Err() == nil {
				st.again = false
				r.mu.Unlock()
				continue
			}
			delete(r.syncs, path)
			r.mu.Unlock()
			return
		}
	}()
}

func (r *Relay) syncOnce(ctx context.Context, path string) {
	if err := r.postSync(ctx, path); err != nil {
		level := slog.LevelWarn
		if errors.Is(err, ErrPeerUnreachable) || ctx.Err() != nil {
			level = slog.LevelDebug
		}
		slog.Log(ctx, level, "peer events: could not ask peer to sync", "socket", path, "error", err)
		return
	}
	slog.Info("peer events: asked peer to sync", "socket", path)
}
