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
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, peerResponseBodyLimit)).Decode(&body)
		return &StatusError{Status: resp.StatusCode, Message: body.Error}
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 4096), eventLineLimit)
	var name, data string
	for sc.Scan() {
		idle.Reset(EventIdleTimeout)
		line := sc.Text()
		switch {
		case line == "":
			// A blank line ends one event.
			if name == "kv-write" && data != "" {
				var e events.Event
				if err := json.Unmarshal([]byte(data), &e); err == nil && e.Key != "" {
					fn(e)
				} else {
					slog.Debug("peer events: malformed event; ignoring", "socket", socketPath)
				}
			}
			name, data = "", ""
		case strings.HasPrefix(line, ":"):
			// Comment: the peer's heartbeat. Its only job is the Reset above.
		case strings.HasPrefix(line, "event:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return io.EOF
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
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, peerResponseBodyLimit)).Decode(&body)
		return &StatusError{Status: resp.StatusCode, Message: body.Error}
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
)

// Relay listens to every live member of a Pool for secret-write notices and
// spreads each one: it triggers this host's own sync, and asks every *other*
// member to sync too.
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
type Relay struct {
	pool      *Pool
	localSync func()
	seen      *events.Seen

	// Seams for tests; production uses StreamEvents and PostSync.
	stream   func(ctx context.Context, path string, fn func(events.Event)) error
	postSync func(ctx context.Context, path string) error
	interval time.Duration

	kick chan struct{}

	mu      sync.Mutex
	streams map[string]context.CancelFunc
	wg      sync.WaitGroup
}

// NewRelay builds a relay over pool. localSync is called for every new
// notice; it must not block (sync.Engine.TriggerSync does not).
func NewRelay(pool *Pool, localSync func()) *Relay {
	return &Relay{
		pool:      pool,
		localSync: localSync,
		seen:      events.NewSeen(),
		stream:    StreamEvents,
		postSync:  PostSync,
		interval:  relayReconcileInterval,
		kick:      make(chan struct{}, 1),
		streams:   make(map[string]context.CancelFunc),
	}
}

// Kick asks the relay to re-glob the pool now. Safe on a nil Relay.
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
// every stream to stop before returning.
func (r *Relay) Run(ctx context.Context) {
	if r == nil || r.pool == nil || len(r.pool.Patterns()) == 0 {
		return
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	defer r.wg.Wait()
	for {
		r.reconcile(ctx)
		select {
		case <-ctx.Done():
			r.mu.Lock()
			for path, cancel := range r.streams {
				cancel()
				delete(r.streams, path)
			}
			r.mu.Unlock()
			return
		case <-ticker.C:
		case <-r.kick:
		}
	}
}

// reconcile starts a stream for every member without one and stops the
// streams of members that are gone.
func (r *Relay) reconcile(ctx context.Context) {
	live := make(map[string]bool)
	for _, m := range r.pool.Resolve() {
		live[m.Path] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for path, cancel := range r.streams {
		if !live[path] {
			cancel()
			delete(r.streams, path)
		}
	}
	for path := range live {
		if _, ok := r.streams[path]; ok {
			continue
		}
		sctx, cancel := context.WithCancel(ctx)
		r.streams[path] = cancel
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.streamLoop(sctx, path)
		}()
	}
}

func (r *Relay) streamLoop(ctx context.Context, path string) {
	backoff := relayMinBackoff
	for {
		started := time.Now()
		err := r.stream(ctx, path, func(e events.Event) { r.handle(ctx, path, e) })
		if ctx.Err() != nil {
			return
		}
		var se *StatusError
		switch {
		case errors.As(err, &se) && se.Status == http.StatusNotFound:
			slog.Debug("peer events: peer has no events endpoint; retrying later", "socket", path)
			backoff = relayMaxBackoff
		case time.Since(started) >= relayHealthyStream:
			slog.Debug("peer events: stream ended; reconnecting", "socket", path, "error", err)
			backoff = relayMinBackoff
		default:
			slog.Debug("peer events: stream failed; backing off", "socket", path, "backoff", backoff, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < relayMaxBackoff {
			backoff *= 2
			if backoff > relayMaxBackoff {
				backoff = relayMaxBackoff
			}
		}
	}
}

// handle acts on one notice received from source.
func (r *Relay) handle(ctx context.Context, source string, e events.Event) {
	if !r.seen.Admit(e) {
		slog.Debug("peer events: duplicate notice; ignoring", "key", e.Key, "version", e.Version, "socket", source)
		return
	}
	slog.Info("peer events: secret changed on a peer; syncing", "key", e.Key, "version", e.Version, "socket", source)
	if r.localSync != nil {
		r.localSync()
	}
	for _, m := range r.pool.Resolve() {
		if m.Path == source {
			continue
		}
		path := m.Path
		go func() {
			if err := r.postSync(ctx, path); err != nil {
				level := slog.LevelWarn
				if errors.Is(err, ErrPeerUnreachable) {
					level = slog.LevelDebug
				}
				slog.Log(ctx, level, "peer events: could not ask peer to sync", "socket", path, "key", e.Key, "version", e.Version, "error", err)
				return
			}
			slog.Info("peer events: asked peer to sync", "socket", path, "key", e.Key, "version", e.Version)
		}()
	}
}
