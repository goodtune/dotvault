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
// func. Cancel is idempotent and closes the channel.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, subscriberBuffer)
	if h == nil {
		close(ch)
		return ch, func() {}
	}
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, ch)
			h.mu.Unlock()
			close(ch)
		})
	}
}

// seenPerKey is how many recent versions Seen remembers for each key.
// Duplicates arrive close together (the same write reported by two desktops,
// or replayed after a reconnect), so a short window catches them.
const seenPerKey = 8

// Seen deduplicates events by remembering the most recent versions observed
// for each key. The same write can reach a receiver more than once, and
// acting on it twice would mean a second local sync and a second round of
// relays for nothing.
//
// It remembers exact versions rather than a high-water mark on purpose: a
// secret that is wiped (a revoked credential) and enrolled again restarts at
// KVv2 version 1, and a high-water mark would then discard every event for
// that key until the new versions overtook the old. The cost is that an
// event older than the window is admitted again, which costs one redundant
// sync.
type Seen struct {
	mu       sync.Mutex
	versions map[string][]int
}

// NewSeen returns an empty deduplicator.
func NewSeen() *Seen {
	return &Seen{versions: make(map[string][]int)}
}

// Admit reports whether e has not been seen before, and records it if so.
func (s *Seen) Admit(e Event) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	recent := s.versions[e.Key]
	for _, v := range recent {
		if v == e.Version {
			return false
		}
	}
	recent = append(recent, e.Version)
	if len(recent) > seenPerKey {
		recent = recent[len(recent)-seenPerKey:]
	}
	s.versions[e.Key] = recent
	return true
}
