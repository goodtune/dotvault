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

// TestEffectivePersistTokenAtRest pins the pre-push review finding: several
// cmd/dotvault call sites (startup reuse, the lifecycle manager's file path,
// the token-file watcher, dotvault status, dotvault enrol) must treat the
// token file as an ordinary candidate under borrow_only, even when
// auth_method happens to be the literal "mtls+os" — because auth_method's
// own no-persist guarantee is moot once no cert flow is ever going to run.
func TestEffectivePersistTokenAtRest(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		borrowOnly bool
		want       bool
	}{
		{"mtls+os without borrow_only excludes the file", "mtls+os", false, false},
		{"mtls+os with borrow_only includes the file", "mtls+os", true, true},
		{"plain mtls always includes the file", "mtls", false, true},
		{"plain mtls with borrow_only still includes the file", "mtls", true, true},
		{"oidc with borrow_only includes the file", "oidc", true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Vault: config.VaultConfig{AuthMethod: tc.method, BorrowOnly: tc.borrowOnly}}
			if got := effectivePersistTokenAtRest(cfg); got != tc.want {
				t.Errorf("effectivePersistTokenAtRest(method=%q, borrow_only=%v) = %v, want %v", tc.method, tc.borrowOnly, got, tc.want)
			}
		})
	}
}

// TestMTLSParamsNilUnderBorrowOnly pins the borrow-only carve-out: even when
// auth_method is a cert method — plausible when it's inherited unchanged from
// a shared base config, since borrow_only documents auth_method as ignored —
// mtlsParams must return nil. Every runDaemon site that wires cert-specific
// behaviour (unattended recovery via lm.SetRecover, the periodic reissue
// check) keys off this nil, so a regression here would silently re-enable a
// borrow-only host's own certificate flow.
func TestMTLSParamsNilUnderBorrowOnly(t *testing.T) {
	for _, method := range []string{"mtls", "mtls+tpm", "mtls+os"} {
		cfg := &config.Config{Vault: config.VaultConfig{
			Address:     "https://vault.example.com",
			AuthMethod:  method,
			TokenSocket: "~/.ssh/dotvault.sock",
			BorrowOnly:  true,
			MTLS: config.MTLSConfig{
				CertRole: "dv", PKIRole: "dv-client",
			},
		}}
		if p := mtlsParams(cfg, "alice"); p != nil {
			t.Errorf("mtlsParams(%q, borrow_only=true) = %+v, want nil", method, p)
		}
	}
}
