package configsvc

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Identity is the authenticated principal on an admin request: a human
// admin who logged in with LDAP credentials (kind "user"), or a service
// account that presented a verified client certificate (kind
// "service-account").
type Identity struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Groups []string `json:"groups,omitempty"`
}

const (
	identityKindUser           = "user"
	identityKindServiceAccount = "service-account"
)

// sessionCookieName carries the admin session. HttpOnly + SameSite=Strict;
// Secure when the login request arrived over TLS.
const sessionCookieName = "dotvault_config_session"

// maxSessions bounds the in-memory session map; at the cap, expired entries
// are swept and — if every session is still live — the map is dropped
// wholesale, logging everyone out rather than growing without bound.
// Sessions are deliberately in-memory only — a service restart logs admins
// out, which is fine for an operator tool.
const maxSessions = 1000

type session struct {
	identity Identity
	expires  time.Time
}

type sessionStore struct {
	ttl time.Duration
	now func() time.Time

	mu       sync.Mutex
	sessions map[string]session
}

func newSessionStore(ttl time.Duration) *sessionStore {
	return &sessionStore{
		ttl:      ttl,
		now:      time.Now,
		sessions: make(map[string]session),
	}
}

func (s *sessionStore) create(identity Identity) string {
	id := randomToken()
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= maxSessions {
		for k, v := range s.sessions {
			if !now.Before(v.expires) {
				delete(s.sessions, k)
			}
		}
		if len(s.sessions) >= maxSessions {
			s.sessions = make(map[string]session)
		}
	}
	s.sessions[id] = session{identity: identity, expires: now.Add(s.ttl)}
	return id
}

func (s *sessionStore) get(id string) (Identity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Identity{}, false
	}
	if !s.now().Before(sess.expires) {
		delete(s.sessions, id)
		return Identity{}, false
	}
	return sess.identity, true
}

func (s *sessionStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// csrfStore issues one-time CSRF tokens for cookie-authenticated mutating
// requests — the same model as the daemon's web UI. Certificate-
// authenticated requests carry no ambient browser credential, so they are
// exempt (a cross-site page cannot wield the caller's client cert through
// a forged request to a different listener).
const (
	maxCSRFTokens = 1000
	csrfTokenTTL  = time.Hour
)

type csrfStore struct {
	now func() time.Time

	mu     sync.Mutex
	tokens map[string]time.Time
}

func newCSRFStore() *csrfStore {
	return &csrfStore{now: time.Now, tokens: make(map[string]time.Time)}
}

func (c *csrfStore) issue() string {
	token := randomToken()
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.tokens) >= maxCSRFTokens {
		for k, exp := range c.tokens {
			if !now.Before(exp) {
				delete(c.tokens, k)
			}
		}
		if len(c.tokens) >= maxCSRFTokens {
			c.tokens = make(map[string]time.Time)
		}
	}
	c.tokens[token] = now.Add(csrfTokenTTL)
	return token
}

// consume validates and invalidates a token (one-time use).
func (c *csrfStore) consume(token string) bool {
	if token == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.tokens[token]
	if !ok {
		return false
	}
	delete(c.tokens, token)
	return c.now().Before(exp)
}

// randomToken returns 32 random bytes hex-encoded. A session or CSRF token
// minted from weak randomness would be guessable, so a randomness failure is
// unrecoverable — panic rather than continue. (Modern Go aborts inside
// rand.Read anyway; the explicit check makes the contract visible.)
func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("configsvc: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// loginLimiter throttles login attempts per client address: the service has
// no loopback invariant, so without it /v1/admin/auth/login is an
// unthrottled online password-guessing oracle against the directory. A
// fixed window is deliberately primitive — it bounds the guess rate; it is
// not a lockout policy.
const (
	loginWindow     = time.Minute
	loginLimit      = 10
	maxLoginBuckets = 4096
)

type loginBucket struct {
	count int
	reset time.Time
}

type loginLimiter struct {
	now func() time.Time

	mu      sync.Mutex
	buckets map[string]loginBucket
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{now: time.Now, buckets: make(map[string]loginBucket)}
}

// allow records an attempt from addr and reports whether it is within the
// window's budget.
func (l *loginLimiter) allow(addr string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[addr]
	if !ok || now.After(b.reset) {
		if len(l.buckets) >= maxLoginBuckets {
			for k, v := range l.buckets {
				if now.After(v.reset) {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) >= maxLoginBuckets {
				l.buckets = make(map[string]loginBucket)
			}
		}
		b = loginBucket{reset: now.Add(loginWindow)}
	}
	b.count++
	l.buckets[addr] = b
	return b.count <= loginLimit
}
