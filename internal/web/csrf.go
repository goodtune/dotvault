package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
)

// maxCSRFTokens is the maximum number of CSRF tokens stored at once.
// When the limit is reached, the oldest token is evicted.
const maxCSRFTokens = 1000

// CSRFStore manages CSRF token generation and validation.
type CSRFStore struct {
	mu     sync.RWMutex
	tokens map[string]bool
	order  []string // tracks insertion order for eviction
}

// NewCSRFStore creates a new CSRF token store.
func NewCSRFStore() *CSRFStore {
	return &CSRFStore{
		tokens: make(map[string]bool),
		order:  make([]string, 0, maxCSRFTokens),
	}
}

// IssueHandler returns an HTTP handler that issues a new CSRF token.
func (cs *CSRFStore) IssueHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := cs.generate()
		if err != nil {
			http.Error(w, "failed to generate token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	}
}

// Validate checks if the request contains a valid CSRF token.
func (cs *CSRFStore) Validate(r *http.Request) bool {
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		return false
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.tokens[token] {
		delete(cs.tokens, token) // One-time use
		return true
	}
	return false
}

func (cs *CSRFStore) generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	cs.mu.Lock()
	// Evict the oldest token if we are at capacity.
	if len(cs.order) >= maxCSRFTokens {
		oldest := cs.order[0]
		cs.order = cs.order[1:]
		delete(cs.tokens, oldest)
	}
	cs.tokens[token] = true
	cs.order = append(cs.order, token)
	cs.mu.Unlock()

	return token, nil
}
