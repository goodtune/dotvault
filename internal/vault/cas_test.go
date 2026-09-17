package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A check-and-set refusal and a malformed request are both 400, so the
// distinction has to come from the body. Reading the status alone would
// report a client bug as "somebody else edited this" and send the user round
// a retry that could never succeed; reading it too loosely would do the same
// for every 400 Vault ever answers.
func TestWriteKVv2CASDistinguishesRefusalFromOtherBadRequests(t *testing.T) {
	for _, tc := range []struct {
		name    string
		errors  []string
		status  int
		wantCAS bool
	}{
		{
			name:    "check-and-set refusal",
			errors:  []string{"check-and-set parameter did not match the current version"},
			status:  http.StatusBadRequest,
			wantCAS: true,
		},
		{
			name:   "some other bad request",
			errors: []string{"failed to parse JSON input: invalid character 'x'"},
			status: http.StatusBadRequest,
		},
		{
			name:   "check-and-set required, which is a configuration error",
			errors: []string{"check-and-set parameter required for this call"},
			status: http.StatusBadRequest,
		},
		{
			name:   "permission denied",
			errors: []string{"permission denied"},
			status: http.StatusForbidden,
		},
		{
			name:   "vault is unwell",
			errors: []string{"internal error"},
			status: http.StatusInternalServerError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				json.NewEncoder(w).Encode(map[string]any{"errors": tc.errors})
			}))
			defer ts.Close()

			c, err := NewClient(Config{Address: ts.URL})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			err = c.WriteKVv2CAS(context.Background(), "kv", "users/testuser/personal/token",
				map[string]any{"value": "v"}, 3)
			if err == nil {
				t.Fatal("write succeeded against an error response")
			}
			if got := errors.Is(err, ErrCASMismatch); got != tc.wantCAS {
				t.Errorf("errors.Is(err, ErrCASMismatch) = %v, want %v (err = %v)", got, tc.wantCAS, err)
			}
		})
	}
}

// The cas option is what the whole guarantee rests on, so pin that it reaches
// Vault on the wire rather than being dropped silently.
func TestWriteKVv2CASSendsTheVersion(t *testing.T) {
	var body map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": 4}})
	}))
	defer ts.Close()

	c, err := NewClient(Config{Address: ts.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.WriteKVv2CAS(context.Background(), "kv", "users/testuser/personal/token",
		map[string]any{"value": "v"}, 3); err != nil {
		t.Fatalf("WriteKVv2CAS: %v", err)
	}
	opts, ok := body["options"].(map[string]any)
	if !ok {
		t.Fatalf("request carried no options block: %v", body)
	}
	if got, _ := opts["cas"].(float64); got != 3 {
		t.Errorf("options.cas = %v, want 3", opts["cas"])
	}
}
