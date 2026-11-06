package client

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/events"
	"github.com/goodtune/dotvault/internal/peer"
)

// Event reports that a secret in the user's own key space was written.
//
// Key is relative to the user's prefix — the same name ReadUserSecret takes as
// its service, such as "gh" or "databricks/prod". Version is the KVv2 version
// the write produced. An Event never carries the secret's value: re-read it
// (ReadUserSecret, ReadKVField) when you need the new contents.
//
// An Event means Vault holds a new version. A rendered file the daemon keeps
// (a sync rule's target) is rewritten by the daemon's own sync, which the same
// write triggers, so it may land a moment later.
type Event struct {
	Key     string
	Version int
	// Source names what wrote the secret, when the daemon knows: "refresh"
	// for a credential rotation, "watch" for a mirrored copy. It may be empty.
	Source string
	// Time is when this client received the notice. A peer's own timestamp
	// is not trusted, so this is not when the write happened.
	Time time.Time
}

// ErrSubscriptionClosed is returned by Subscription.Next once the
// subscription has been closed.
var ErrSubscriptionClosed = errors.New("dotvault: subscription closed")

// Subscribe starts listening for writes to the user's secrets, so a program
// can react when a credential it uses is rotated underneath it instead of
// re-reading on a timer.
//
// It listens to the local daemon's API socket when one is configured
// (APISocket, from api.enabled; Linux and macOS): that daemon carries its own
// writes and re-announces everything it relays from its peers, so listening
// to the peers as well would only duplicate the stream and hold a subscriber
// slot on each of them. With no API socket — a host without a local daemon,
// or Windows — it listens to every peer in TokenSockets instead, and the same
// write heard from several of them is delivered once.
//
// A socket that is absent or goes away is retried in the background for the
// life of the subscription — a restarted daemon is picked up within about 30
// seconds — so Subscribe succeeds even when no daemon is listening yet; it
// fails only when no socket is configured at all, with ErrPeerUnavailable.
//
// The subscription runs until Close is called or ctx is cancelled. Read
// events with Next.
func (c *Client) Subscribe(ctx context.Context) (*Subscription, error) {
	sockets := c.cfg.Vault.TokenSockets
	if c.cfg.Vault.APISocket != "" {
		sockets = []string{c.cfg.Vault.APISocket}
	}
	if len(sockets) == 0 {
		return nil, fmt.Errorf("%w: no dotvault socket configured (set api.enabled or vault.token_socket)", ErrPeerUnavailable)
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Subscription{
		pending: make(map[string]Event),
		notify:  make(chan struct{}, 1),
		done:    make(chan struct{}),
		cancel:  cancel,
	}
	relay := peer.NewRelay(peer.NewPool(sockets), s.push)
	go func() {
		defer close(s.done)
		relay.Run(ctx)
	}()
	return s, nil
}

// maxPending bounds how many distinct keys a Subscription holds undelivered.
// A user has a handful of secrets, so reaching it means a consumer that is not
// reading while something streams distinct keys at it; the oldest pending key
// is then dropped rather than growing without limit.
const maxPending = 1024

// Subscription delivers Events from Subscribe. It is safe for concurrent use,
// including several goroutines calling Next.
//
// Undelivered events are coalesced per key: if a key is written twice before
// Next is called, Next reports only the later write (the higher version, if
// two sockets report out of order). A slow consumer therefore never loses the
// current state of a key, only intermediate versions it would have re-read
// past anyway — unless more than maxPending distinct keys pile up unread.
type Subscription struct {
	mu      sync.Mutex
	pending map[string]Event
	order   []string // keys in pending, oldest first
	notify  chan struct{}
	done    chan struct{}
	cancel  context.CancelFunc
	closed  bool
}

func (s *Subscription) push(e events.Event) {
	s.mu.Lock()
	if prev, ok := s.pending[e.Key]; ok {
		if e.Version > prev.Version {
			s.pending[e.Key] = toEvent(e)
		}
	} else {
		if len(s.order) >= maxPending {
			delete(s.pending, s.order[0])
			s.order = s.order[1:]
		}
		s.order = append(s.order, e.Key)
		s.pending[e.Key] = toEvent(e)
	}
	s.mu.Unlock()
	s.signal()
}

func toEvent(e events.Event) Event {
	return Event{Key: e.Key, Version: e.Version, Source: e.Source, Time: e.Time}
}

// signal wakes one waiting Next. The channel holds a single token, so a Next
// that takes an event and leaves more behind passes the token on (see Next);
// otherwise a second waiting reader could sleep beside a pending event.
func (s *Subscription) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// Next blocks until an event is available and returns it, or returns ctx's
// error if ctx ends first, or ErrSubscriptionClosed once the subscription is
// closed (by Close, or by cancellation of the context Subscribe was given).
func (s *Subscription) Next(ctx context.Context) (Event, error) {
	for {
		s.mu.Lock()
		// Anything already received is delivered before the closed state is
		// reported; Close discards it explicitly.
		if len(s.order) > 0 {
			key := s.order[0]
			s.order = s.order[1:]
			e := s.pending[key]
			delete(s.pending, key)
			more := len(s.order) > 0
			s.mu.Unlock()
			if more {
				s.signal()
			}
			return e, nil
		}
		if s.closed {
			s.mu.Unlock()
			return Event{}, ErrSubscriptionClosed
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return Event{}, ctx.Err()
		case <-s.done:
			s.mu.Lock()
			s.closed = true
			s.mu.Unlock()
		case <-s.notify:
		}
	}
}

// Close stops the subscription and waits for its background work to end.
// It is idempotent. Pending undelivered events are discarded.
func (s *Subscription) Close() error {
	s.cancel()
	<-s.done
	s.mu.Lock()
	s.closed = true
	s.pending = map[string]Event{}
	s.order = nil
	s.mu.Unlock()
	return nil
}
