package main

import (
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

// TestMTLSParamsRevocationDefault pins the one path a user actually gets: a
// config that never mentions revoke_superseded must produce params that revoke.
//
// This is the seam where a tri-state becomes a plain bool, and it is exactly
// where a default can be lost — the field is spelled negatively so the zero
// value is safe, which means the wiring has to invert, and an inversion is the
// kind of thing that survives review while being backwards.
func TestMTLSParamsRevocationDefault(t *testing.T) {
	no, yes := false, true
	tests := []struct {
		name     string
		set      *bool
		wantSkip bool
	}{
		{"unmentioned revokes", nil, false},
		{"explicit true revokes", &yes, false},
		{"explicit false opts out", &no, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Vault: config.VaultConfig{
				Address:    "https://vault.example.com",
				AuthMethod: "mtls",
				MTLS: config.MTLSConfig{
					CertRole: "dv", PKIRole: "dv-client",
					RevokeSuperseded: tc.set,
				},
			}}
			p := mtlsParams(cfg, "alice")
			if p == nil {
				t.Fatal("mtlsParams returned nil for an mtls method")
			}
			if p.SkipRevokeSuperseded != tc.wantSkip {
				t.Errorf("SkipRevokeSuperseded = %v, want %v", p.SkipRevokeSuperseded, tc.wantSkip)
			}
		})
	}
}
