// Package groups resolves a username to the set of configuration groups it
// belongs to — the group/<g> dimension of layer composition. Two resolvers
// exist behind the Resolver interface: static membership maps held in the
// store (dev/test and small fleets) and LDAP for the directory-driven case.
// Both are normally wrapped in the TTL cache so a burst of requests for the
// same user costs one backend lookup.
package groups

import (
	"context"
	"sync"
	"time"
)

// Resolver maps a username to group names. An unknown user resolves to an
// empty list, not an error — composing global+os for an unknown user is
// valid. Errors are reserved for backend failures (the server answers 500,
// and the client fails open to its cache).
type Resolver interface {
	Groups(ctx context.Context, user string) ([]string, error)
}

// maxCacheEntries bounds the cache map. The service is unauthenticated and
// the username dimension is client-asserted, so an attacker can iterate
// arbitrary usernames; without a cap that grows memory without limit. At the
// cap, expired entries are swept and — if every entry is still live — the
// map is dropped wholesale, trading a burst of backend lookups for bounded
// memory.
const maxCacheEntries = 4096

// cached wraps a Resolver with a TTL cache. Successful lookups (including
// empty memberships) are cached; errors are not, so a transient backend
// failure is retried on the next request rather than pinned for a TTL.
type cached struct {
	inner Resolver
	ttl   time.Duration
	now   func() time.Time

	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	groups  []string
	expires time.Time
}

// NewCached wraps inner with a TTL cache. A non-positive ttl returns inner
// unwrapped.
func NewCached(inner Resolver, ttl time.Duration) Resolver {
	if ttl <= 0 {
		return inner
	}
	return &cached{
		inner:   inner,
		ttl:     ttl,
		now:     time.Now,
		entries: make(map[string]cacheEntry),
	}
}

func (c *cached) Groups(ctx context.Context, user string) ([]string, error) {
	now := c.now()
	c.mu.Lock()
	if e, ok := c.entries[user]; ok && now.Before(e.expires) {
		groups := append([]string(nil), e.groups...)
		c.mu.Unlock()
		return groups, nil
	}
	c.mu.Unlock()

	groups, err := c.inner.Groups(ctx, user)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if len(c.entries) >= maxCacheEntries {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= maxCacheEntries {
			c.entries = make(map[string]cacheEntry)
		}
	}
	c.entries[user] = cacheEntry{groups: append([]string(nil), groups...), expires: now.Add(c.ttl)}
	c.mu.Unlock()
	return groups, nil
}
