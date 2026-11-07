// Package events carries change notices about the user's own KV secrets
// between the parts of a daemon, and between daemons over the peer socket.
//
// An Event says that a secret was written and which KVv2 version the write
// produced. It never carries a value: a receiver that cares re-reads Vault,
// so an event is a hint to look rather than a copy of anything, and a forged
// or replayed one costs at most a redundant read.
//
// The package is a leaf (it imports nothing internal) because both the
// producer side (cmd/dotvault wiring the enrolment managers, internal/web
// serving the stream) and the consumer side (internal/peer relaying it)
// need the one definition.
package events

import (
	"errors"
	"log/slog"
	"sync"
	"time"
)

// Event reports a write to a secret under the user's KV prefix.
//
// Key is relative to the user prefix (an enrolment key such as "gh" or
// "databricks/prod"), never a full Vault path, so a receiver configured with
// a different mount or prefix still reads the same name. Version is the KVv2
// version the write produced and is what lets a receiver discard an event it
// has already acted on (see Seen).
type Event struct {
	Key     string    `json:"key"`
	Version int       `json:"version"`
	Source  string    `json:"source,omitempty"`
	Time    time.Time `json:"time"`
}

// subscriberBuffer bounds how many events a slow subscriber can fall behind
// before further events to it are dropped. Events are hints and writes are
// infrequent (a rotation every few hours), so a full buffer means a stalled
// reader rather than a burst worth queueing for.
const subscriberBuffer = 32

// MaxSubscribers bounds concurrent subscriptions to one hub. Each holds a
// goroutine and a connection in the HTTP handler, and the loopback listener
// is reachable by every local user, so the bound is what stops one of them
// from opening streams until the daemon runs out of descriptors. A daemon's
// legitimate subscribers are the handful of hosts that borrow from it.
const MaxSubscribers = 64

// ErrTooManySubscribers is returned by Subscribe when the hub is full.
var ErrTooManySubscribers = errors.New("too many event subscribers")

// Hub fans events out to every current subscriber. It is safe for
// concurrent use, and every method is nil-receiver safe so a caller with no
// hub wired needs no branch.
type Hub struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

// NewHub returns an empty hub.
func NewHub() *Hub {
	return &Hub{subs: make(map[chan Event]struct{})}
}

// Publish delivers e to every subscriber without blocking. A subscriber
// whose buffer is full misses the event; the drop is logged at debug.
func (h *Hub) Publish(e Event) {
	if h == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- e:
		default:
			slog.Debug("events: subscriber not keeping up, dropping event", "key", e.Key, "version", e.Version)
		}
	}
}

// Subscribe registers a subscriber and returns its channel and a cancel
// func, or ErrTooManySubscribers when the hub already has MaxSubscribers.
// Cancel is idempotent and closes the channel. A nil hub hands out a
// channel that carries nothing until cancelled: a stream with no hub behind
// it is quiet, not broken.
func (h *Hub) Subscribe() (<-chan Event, func(), error) {
	ch := make(chan Event, subscriberBuffer)
	var once sync.Once
	if h == nil {
		return ch, func() { once.Do(func() { close(ch) }) }, nil
	}
	h.mu.Lock()
	if len(h.subs) >= MaxSubscribers {
		h.mu.Unlock()
		return nil, nil, ErrTooManySubscribers
	}
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, ch)
			h.mu.Unlock()
			close(ch)
		})
	}, nil
}

// seenPerKey is how many recent versions Seen remembers for each key.
// Duplicates arrive close together (the same write reported by two desktops,
// or replayed after a reconnect), so a short window catches them.
const seenPerKey = 8

// maxSeenKeys bounds how many keys Seen tracks. Keys arrive from peers, so
// without a bound a hostile one could grow the table indefinitely. A user has
// a handful of enrolments; reaching the bound means something is wrong, and
// starting over costs at most one redundant sync per key.
const maxSeenKeys = 1024

// Seen deduplicates events by remembering the most recent versions observed
// for each key. The same write can reach a receiver more than once, and
// acting on it twice would mean a second local sync and a second round of
// relays for nothing.
//
// It remembers exact versions rather than a high-water mark, and starts a
// key's window afresh when a version lower than any in it arrives. Both are
// for the same case: a revoked secret is wiped and re-enrolled, which
// restarts its KVv2 versions at 1. A high-water mark would discard every
// event for that key until the new versions overtook the old, and a window
// that kept the old versions would discard the new life's version 2 if the
// old life's version 2 were still in it. The cost of the reset is that an
// older event arriving out of order also clears the window, which costs one
// redundant sync. One case it cannot see: an old life that never got past
// the window's lowest version (wiped at v3, say) looks identical to the new
// life's first versions, which are then dropped as duplicates. A receiver's
// refresh check still notices the version change on its next tick.
type Seen struct {
	mu       sync.Mutex
	versions map[string][]int
}

// NewSeen returns an empty deduplicator.
func NewSeen() *Seen {
	return &Seen{versions: make(map[string][]int)}
}

// Admit reports whether e should be acted on, and records it if so. An event
// whose version is not positive is never admitted: KVv2 versions start at 1,
// so such an event carries no version and recording it would make every later
// version-less event for the key look like a duplicate.
func (s *Seen) Admit(e Event) bool {
	if e.Version <= 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recent, ok := s.versions[e.Key]
	if !ok && len(s.versions) >= maxSeenKeys {
		slog.Warn("events: too many distinct keys seen; resetting the deduplication table", "keys", len(s.versions))
		s.versions = make(map[string][]int)
	}
	lowest := 0
	for _, v := range recent {
		if v == e.Version {
			return false
		}
		if lowest == 0 || v < lowest {
			lowest = v
		}
	}
	if e.Version < lowest {
		recent = nil // the secret was deleted and recreated
	}
	recent = append(recent, e.Version)
	if len(recent) > seenPerKey {
		recent = recent[len(recent)-seenPerKey:]
	}
	s.versions[e.Key] = recent
	return true
}
