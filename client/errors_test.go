package client

import (
	"errors"
	"net/http"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   error
	}{
		{"unauthorized", http.StatusUnauthorized, ErrDenied},
		{"forbidden", http.StatusForbidden, ErrDenied},
		// Guards that a generic 4xx stays in the denied bucket — i.e. the
		// 429 carve-out below didn't accidentally redirect all 4xx.
		{"bad request", http.StatusBadRequest, ErrDenied},
		{"too many requests", http.StatusTooManyRequests, ErrUnreachable},
		{"internal", http.StatusInternalServerError, ErrUnreachable},
		{"bad gateway", http.StatusBadGateway, ErrUnreachable},
		{"service unavailable", http.StatusServiceUnavailable, ErrUnreachable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classify(&vaultapi.ResponseError{StatusCode: tt.status})
			if !errors.Is(got, tt.want) {
				t.Fatalf("classify(%d) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestClassify_NoHTTPResponse(t *testing.T) {
	// A transport error (no *vaultapi.ResponseError in the chain) is
	// "couldn't talk to Vault" → ErrUnreachable.
	if got := classify(errors.New("dial tcp: connection refused")); !errors.Is(got, ErrUnreachable) {
		t.Fatalf("classify(transport) = %v, want ErrUnreachable", got)
	}
}

func TestClassify_Nil(t *testing.T) {
	if got := classify(nil); got != nil {
		t.Fatalf("classify(nil) = %v, want nil", got)
	}
}
