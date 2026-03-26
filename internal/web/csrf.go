package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
)

// CSRFStore manages CSRF token generation and validation.
type CSRFStore struct {
	mu     sync.RWMutex
	tokens map[string]bool
}

// NewCSRFStore creates a new CSRF token store.
func NewCSRFStore() *CSRFStore {
	return &CSRFStore{
		tokens: make(map[string]bool),
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
	cs.tokens[token] = true
	cs.mu.Unlock()

	return token, nil
}
