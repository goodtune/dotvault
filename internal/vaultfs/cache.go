package vaultfs

import (
	"sync"
	"time"
)

// cache holds directory listings and rendered documents for a short window.
//
// It is not an optimisation so much as a requirement. A filesystem asks far
// more questions than a person does: `ls -l` stats every entry, shell
// completion stats speculatively, and stat on a secret file needs the file's
// size, which can only be known by rendering the document — so an uncached
// mount would turn one `ls -l` into one Vault read per secret, every time.
//
// Misses are cached too. A lookup for a name that does not exist is the most
// common request a mounted filesystem receives (every tab-completion, every
// tool probing for a config file), and without negative caching each one costs
// a Vault round trip.
//
// The window is deliberately short and fixed rather than event-driven: a stale
// read resolves itself within the TTL, and a write through the mount
// invalidates the affected entries immediately, so the only staleness a user
// can observe is a secret changed by something else within the last TTL.
type cache struct {
	ttl time.Duration
	// now is injectable so the TTL can be tested without sleeping.
	now func() time.Time

	mu   sync.Mutex
	dirs map[string]dirEntry
	docs map[string]docEntry
}

type dirEntry struct {
	entries []Entry
	expires time.Time
}

type docEntry struct {
	// doc is nil for a negative entry: the path was looked up and no secret
	// exists there.
	doc     *Document
	expires time.Time
}

func newCache(ttl time.Duration) *cache {
	return &cache{
		ttl:  ttl,
		now:  time.Now,
		dirs: make(map[string]dirEntry),
		docs: make(map[string]docEntry),
	}
}

// enabled reports whether the cache stores anything. A zero (or negative) TTL
// disables it entirely, which is the escape hatch for anyone who would rather
// pay a Vault round trip per operation than ever see a stale read.
func (c *cache) enabled() bool { return c != nil && c.ttl > 0 }

func (c *cache) lookupDir(path string) ([]Entry, bool) {
	if !c.enabled() {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.dirs[path]
	if !ok || c.now().After(e.expires) {
		return nil, false
	}
	return e.entries, true
}

func (c *cache) storeDir(path string, entries []Entry) {
	if !c.enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dirs[path] = dirEntry{entries: entries, expires: c.now().Add(c.ttl)}
}

// lookupDoc returns (doc, true) for a cached hit — doc is nil when the cached
// answer is "no secret here" — and (nil, false) when nothing usable is cached.
func (c *cache) lookupDoc(path string) (*Document, bool) {
	if !c.enabled() {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.docs[path]
	if !ok || c.now().After(e.expires) {
		return nil, false
	}
	return e.doc, true
}

func (c *cache) storeDoc(path string, doc *Document) {
	if !c.enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.docs[path] = docEntry{doc: doc, expires: c.now().Add(c.ttl)}
}

// invalidate drops everything the mount could have learned about path: the
// document itself, and the listing of the directory containing it (a create or
// a delete changes that listing's membership).
//
// It is called after every successful write through the mount, so a read
// following a write in the same shell pipeline sees what was just written
// rather than the pre-write cache entry.
func (c *cache) invalidate(path string) {
	if !c.enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.docs, path)
	delete(c.dirs, parentPath(path))
}

// invalidateAll drops every entry. Used when the caller has reason to believe
// the whole view is stale — a token change, a manual refresh.
func (c *cache) invalidateAll() {
	if !c.enabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.dirs)
	clear(c.docs)
}
