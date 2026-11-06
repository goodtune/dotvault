package web

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// eventsHeartbeat is how often an idle event stream sends an SSE comment.
// It keeps intermediaries from timing the connection out, and gives a
// subscriber a regular signal it can watch to notice a stream that has
// silently died — an SSH forward whose far side went away can leave the
// local half of the connection open indefinitely. peer.EventIdleTimeout is
// the subscriber's side of that bargain and must stay comfortably above it.
const eventsHeartbeat = 25 * time.Second

// eventsKVWrite is the SSE event name for a secret-write notice.
const eventsKVWrite = "kv-write"

// handleEvents streams secret-write notices as Server-Sent Events:
//
//	event: kv-write
//	id: gh@31
//	data: {"key":"gh","version":31,"source":"refresh","time":"…"}
//
// It is how a host borrowing this daemon's token over the peer socket learns
// that a secret changed without waiting for its own sync poll — the gap that
// matters most on Vault Community, which has no event API of its own. The
// stream carries the key (relative to the user prefix) and the KVv2 version
// the write produced, so a subscriber can recognise the same write arriving
// twice; it never carries a value, which the subscriber re-reads from Vault.
//
// It reveals no more than GET /api/v1/secrets/ already lists on the same
// listeners, and less than GET /api/v1/token, so it takes the same posture:
// no CSRF gate (a GET that changes nothing) and no token check (a subscriber
// should be able to connect before this daemon has authenticated, and simply
// hear nothing until it writes). A cross-origin page cannot read it — the
// response carries no CORS headers — and the middleware's Host check stops a
// rebinding page from making it same-origin. Concurrent streams are capped
// at events.MaxSubscribers, since the loopback listener is reachable by
// every local user and each stream holds a goroutine and a descriptor.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)

	ch, cancel, err := s.events.Subscribe()
	if err != nil {
		writeError(w, "too many event subscribers", http.StatusServiceUnavailable)
		return
	}
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	// An opening comment commits the headers, so a subscriber knows the
	// stream is established rather than waiting for the first event.
	if _, err := fmt.Fprint(w, ": connected\n\n"); err != nil {
		return
	}
	if err := rc.Flush(); err != nil {
		slog.Debug("events: stream cannot flush; closing", "error", err)
		return
	}

	heartbeat := time.NewTicker(eventsHeartbeat)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.shutdownCtx.Done():
			// http.Server.Shutdown waits for active handlers but does not
			// cancel their contexts, so a stream would hold shutdown open for
			// its whole timeout without this.
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			body, err := json.Marshal(e)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "event: %s\nid: %s@%d\ndata: %s\n\n", eventsKVWrite, e.Key, e.Version, body); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		}
	}
}
