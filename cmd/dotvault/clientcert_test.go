package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/clientcert"
	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
)

// forbiddenSigner fails the test on any use: building a source, or reporting
// on one, must not touch Vault.
type forbiddenSigner struct{ t *testing.T }

func (f forbiddenSigner) Token() string { f.t.Error("Token called"); return "" }
func (f forbiddenSigner) LookupSelfWithToken(context.Context, string) (*vaultapi.Secret, error) {
	f.t.Error("LookupSelfWithToken called")
	return nil, errors.New("forbidden")
}
func (f forbiddenSigner) SignCSRWithToken(context.Context, string, string, string, string, string, string) (*vault.IssuedCert, error) {
	f.t.Error("SignCSRWithToken called")
	return nil, errors.New("forbidden")
}

func TestBuildClientCertSourceDisabled(t *testing.T) {
	cfg := &config.Config{}
	if got := buildClientCertSource(cfg, nil, "gary"); got != nil {
		t.Errorf("buildClientCertSource = %v, want nil when client_cert is disabled", got)
	}
}

func TestBuildClientCertSourceEphemeralIsLazy(t *testing.T) {
	cfg := &config.Config{
		Vault:      config.VaultConfig{AuthMethod: "oidc"},
		ClientCert: config.ClientCertConfig{Enabled: true, PKIRole: "client", KeyType: "ec", TTL: 5 * time.Minute},
	}
	src := newClientCertSource(cfg, forbiddenSigner{t}, "gary")
	if src == nil {
		t.Fatal("source not built")
	}
	// Reporting must not sign either.
	if st := clientcert.StatusOf(src); st.State != clientcert.StateIdle {
		t.Errorf("fresh source state = %q, want idle", st.State)
	}
}

func TestBuildClientCertSourceBadConfigIsNotFatal(t *testing.T) {
	// Ephemeral with no role cannot be built; the daemon must carry on.
	cfg := &config.Config{
		Vault:      config.VaultConfig{AuthMethod: "oidc"},
		ClientCert: config.ClientCertConfig{Enabled: true, KeyType: "ec"},
	}
	if got := newClientCertSource(cfg, forbiddenSigner{t}, "gary"); got != nil {
		t.Errorf("source = %v, want nil on a construction error", got)
	}
}

func inspectNever(t *testing.T) func(string) (auth.CertCredentialInfo, error) {
	return func(string) (auth.CertCredentialInfo, error) {
		t.Error("inspected the envelope for a short-lived source")
		return auth.CertCredentialInfo{}, nil
	}
}

func TestPrintClientCertStatusDisabledPrintsNothing(t *testing.T) {
	var b bytes.Buffer
	writeClientCertStatus(&b, &config.Config{}, inspectNever(t))
	if b.Len() != 0 {
		t.Errorf("output = %q, want none", b.String())
	}
}

func TestPrintClientCertStatusShortLived(t *testing.T) {
	cfg := &config.Config{
		Vault:      config.VaultConfig{AuthMethod: "oidc"},
		ClientCert: config.ClientCertConfig{Enabled: true, PKIMount: "pki-int", PKIRole: "client", TTL: 10 * time.Minute},
	}
	var b bytes.Buffer
	writeClientCertStatus(&b, cfg, inspectNever(t))
	out := b.String()
	for _, want := range []string{"Client certificate:", "short-lived", "pki-int", "role client", "10m0s"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestPrintClientCertStatusHeld(t *testing.T) {
	cfg := &config.Config{
		Vault:      config.VaultConfig{AuthMethod: "mtls"},
		ClientCert: config.ClientCertConfig{Enabled: true},
	}
	na := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	var b bytes.Buffer
	writeClientCertStatus(&b, cfg, func(string) (auth.CertCredentialInfo, error) {
		return auth.CertCredentialInfo{Present: true, NotAfter: na}, nil
	})
	out := b.String()
	for _, want := range []string{"held", "valid until 2030-01-02T03:04:05Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "short-lived") {
		t.Errorf("held without a role must not mention a fallback:\n%s", out)
	}
}

func TestPrintClientCertStatusHeldStates(t *testing.T) {
	cfg := &config.Config{
		Vault:      config.VaultConfig{AuthMethod: "mtls", MTLS: config.MTLSConfig{PKIRole: "r"}},
		ClientCert: config.ClientCertConfig{Enabled: true},
	}
	for name, tc := range map[string]struct {
		info auth.CertCredentialInfo
		err  error
		want string
	}{
		"absent":  {want: "no certificate enrolled"},
		"expired": {info: auth.CertCredentialInfo{Present: true, Expired: true, NotAfter: time.Unix(0, 0).UTC()}, want: "expired"},
		"broken":  {err: errors.New("bad envelope"), want: "unreadable (bad envelope)"},
	} {
		t.Run(name, func(t *testing.T) {
			var b bytes.Buffer
			writeClientCertStatus(&b, cfg, func(string) (auth.CertCredentialInfo, error) { return tc.info, tc.err })
			out := b.String()
			if !strings.Contains(out, tc.want) || !strings.Contains(out, "falling back to short-lived") {
				t.Errorf("output missing %q or the fallback note:\n%s", tc.want, out)
			}
		})
	}
}

func TestWarnInheritedClientCertRole(t *testing.T) {
	capture := func(cfg *config.Config) string {
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
		defer slog.SetDefault(prev)
		warnInheritedClientCertRole(cfg)
		return buf.String()
	}

	inherited := &config.Config{
		Vault: config.VaultConfig{
			AuthMethod: "mtls+tpm",
			MTLS:       config.MTLSConfig{PKIRole: "user-client"},
		},
		ClientCert: config.ClientCertConfig{Enabled: true},
	}
	out := capture(inherited)
	for _, want := range []string{"level=WARN", "client_cert.pki_role", "vault.mtls.pki_role", "user-client", "log in to Vault"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning %q does not mention %q", out, want)
		}
	}

	own := *inherited
	own.ClientCert.PKIRole = "tools"
	if out := capture(&own); out != "" {
		t.Errorf("a dedicated role still warned: %q", out)
	}
}

// lifecycleStub is what the daemon wires into the certificate source: the
// lifecycle manager's gate and its rejection report.
type lifecycleStub struct {
	reported []error
}

func (l *lifecycleStub) NeedsReauth() bool        { return false }
func (l *lifecycleStub) NotifyRejected(err error) { l.reported = append(l.reported, err) }

// deniedSigner holds a token and has every sign refused with a 403.
type deniedSigner struct{}

func (deniedSigner) Token() string { return "s.token" }
func (deniedSigner) LookupSelfWithToken(context.Context, string) (*vaultapi.Secret, error) {
	return &vaultapi.Secret{Data: map[string]any{"meta": map[string]any{"username": "gary"}}}, nil
}
func (deniedSigner) SignCSRWithToken(context.Context, string, string, string, string, string, string) (*vault.IssuedCert, error) {
	return nil, &vaultapi.ResponseError{StatusCode: 403, Errors: []string{"permission denied"}}
}

// The daemon wires its lifecycle manager into the certificate source the way
// it does the SSH agent's, so a sign Vault refuses with a 403 starts token
// recovery at once instead of at the lifecycle manager's next poll.
func TestWireClientCertLifecycleReportsRejection(t *testing.T) {
	cfg := &config.Config{
		Vault:      config.VaultConfig{AuthMethod: "oidc"},
		ClientCert: config.ClientCertConfig{Enabled: true, PKIRole: "client", KeyType: "ec", TTL: 5 * time.Minute},
	}
	src := newClientCertSource(cfg, deniedSigner{}, "gary")
	if src == nil {
		t.Fatal("source not built")
	}
	lm := &lifecycleStub{}
	wireClientCertLifecycle(src, lm)
	if _, err := src.Current(context.Background()); err == nil {
		t.Fatal("expected the sign to be refused")
	}
	if len(lm.reported) != 1 {
		t.Fatalf("reported %d rejections, want 1", len(lm.reported))
	}
}

func TestWireClientCertLifecycleToleratesNilAndHeld(t *testing.T) {
	wireClientCertLifecycle(nil, &lifecycleStub{})
	cfg := &config.Config{
		Vault:      config.VaultConfig{AuthMethod: "mtls"},
		ClientCert: config.ClientCertConfig{Enabled: true, KeyType: "ec"},
	}
	if src := newClientCertSource(cfg, forbiddenSigner{t}, "gary"); src != nil {
		wireClientCertLifecycle(src, &lifecycleStub{})
	}
}
