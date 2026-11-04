package clientcert

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/config"
)

// realtimeSigner is a fake CA on the wall clock: New builds its ephemeral
// source with time.Now, so the certificates it issues must be dated by it.
func realtimeSigner(t *testing.T) *fakeSigner {
	t.Helper()
	clock := newTestClock()
	clock.t = time.Now().Truncate(time.Second)
	return newFakeSigner(t, clock)
}

func enabledConfig(method, role string) *config.Config {
	cfg := &config.Config{}
	cfg.Vault.AuthMethod = method
	cfg.ClientCert.Enabled = true
	cfg.ClientCert.PKIRole = role
	cfg.ClientCert.TTL = 5 * time.Minute
	return cfg
}

func TestNewDisabledReturnsNil(t *testing.T) {
	cfg := enabledConfig("mtls", "user-client")
	cfg.ClientCert.Enabled = false
	src, err := New(cfg, nil, "gary", t.TempDir())
	if err != nil || src != nil {
		t.Fatalf("New = %v, %v; want nil, nil", src, err)
	}
}

func TestNewPicksEphemeralForTPMAndOIDC(t *testing.T) {
	for _, method := range []string{"mtls+tpm", "mtls+os", "oidc", "ldap", "token"} {
		t.Run(method, func(t *testing.T) {
			src, err := New(enabledConfig(method, "user-client"), realtimeSigner(t), "gary", t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := src.(*ephemeral); !ok {
				t.Fatalf("source = %T, want *ephemeral", src)
			}
		})
	}
}

func TestNewBorrowOnlyIsEphemeralEvenUnderMTLS(t *testing.T) {
	cfg := enabledConfig("mtls", "user-client")
	cfg.Vault.BorrowOnly = true
	src, err := New(cfg, realtimeSigner(t), "gary", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := src.(*ephemeral); !ok {
		t.Fatalf("source = %T, want *ephemeral", src)
	}
}

func TestNewHeldPrefersHeldWhenPresent(t *testing.T) {
	dir := t.TempDir()
	writeEnvelope(t, dir, envelopeSpec{serial: 0x77})
	signer := realtimeSigner(t)
	src, err := New(enabledConfig("mtls", "user-client"), signer, "gary", dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := src.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != SourceHeld || p.Serial != "77" {
		t.Fatalf("got source %q serial %q", p.Source, p.Serial)
	}
	if signer.signs.Load() != 0 {
		t.Fatal("signed an ephemeral certificate while a held one was usable")
	}
	if lp, _ := src.(lastReporter).Last(); lp != p {
		t.Error("Last does not report the held pair")
	}
}

func TestHeldFallsBackToEphemeral(t *testing.T) {
	signer := realtimeSigner(t)
	cfg := enabledConfig("mtls", "user-client")
	cfg.ClientCert.CommonName = "{{.os_user}}"
	src, err := New(cfg, signer, "gary", t.TempDir()) // no envelope
	if err != nil {
		t.Fatal(err)
	}
	p, err := src.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != SourceEphemeral {
		t.Fatalf("Source = %q, want ephemeral", p.Source)
	}
	if lp, _ := src.(lastReporter).Last(); lp != p {
		t.Error("Last does not report the ephemeral pair that served last")
	}
}

func TestHeldFallbackReturnsToHeldOnceEnrolled(t *testing.T) {
	dir := t.TempDir()
	signer := realtimeSigner(t)
	src, err := New(enabledConfig("mtls", "user-client"), signer, "gary", dir)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := src.Current(context.Background()); err != nil || p.Source != SourceEphemeral {
		t.Fatalf("first: %v, %v", p, err)
	}
	writeEnvelope(t, dir, envelopeSpec{})
	p, err := src.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != SourceHeld {
		t.Fatalf("Source = %q, want held after enrolment", p.Source)
	}
}

func TestHeldNoFallbackWithoutRole(t *testing.T) {
	src, err := New(enabledConfig("mtls", ""), nil, "gary", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = src.Current(context.Background())
	if !errors.Is(err, auth.ErrNoCertCredential) {
		t.Fatalf("err = %v, want the held error", err)
	}
}

func TestHeldNotExportableDoesNotFallBack(t *testing.T) {
	dir := t.TempDir()
	writeEnvelope(t, dir, envelopeSpec{backend: "tpm"})
	signer := realtimeSigner(t)
	src, err := New(enabledConfig("mtls", "user-client"), signer, "gary", dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = src.Current(context.Background())
	if !errors.Is(err, auth.ErrHeldNotExportable) {
		t.Fatalf("err = %v", err)
	}
	if signer.signs.Load() != 0 {
		t.Fatal("fell back to signing for a non-exportable held credential")
	}
}

func TestNewHeldRefusesEmptyUsername(t *testing.T) {
	if _, err := New(enabledConfig("mtls", "user-client"), realtimeSigner(t), "", t.TempDir()); err == nil {
		t.Fatal("a held configuration with no username was accepted")
	}
	// An ephemeral configuration does not use the username for a check.
	if _, err := New(enabledConfig("oidc", "user-client"), realtimeSigner(t), "", t.TempDir()); err != nil {
		t.Fatalf("ephemeral with empty os user: %v", err)
	}
}

func TestNewEphemeralNeedsRole(t *testing.T) {
	if _, err := New(enabledConfig("oidc", ""), realtimeSigner(t), "gary", t.TempDir()); err == nil {
		t.Fatal("ephemeral without a role was accepted")
	}
}

func TestParamsFromConfig(t *testing.T) {
	cfg := enabledConfig("mtls", "")
	cfg.Vault.MTLS.PKIRole = "inherited"
	cfg.Vault.MTLS.PKIMount = "pki-client"
	cfg.Vault.MTLS.ReissueBeforeDur = 48 * time.Hour
	cfg.ClientCert.TTL = 0 // unparsed: the default applies
	p := ParamsFromConfig(cfg, "gary", "/store")
	if !p.Enabled || !p.Held || p.Method != "mtls" || p.StorageDir != "/store" || p.ReissueBefore != 48*time.Hour {
		t.Errorf("params = %+v", p)
	}
	e := p.Ephemeral
	if e.PKIRole != "inherited" || e.PKIMount != "pki-client" || e.OSUser != "gary" ||
		e.TTL != config.DefaultClientCertTTL || e.CommonName != config.DefaultClientCertCommonName {
		t.Errorf("ephemeral options = %+v", e)
	}
}
