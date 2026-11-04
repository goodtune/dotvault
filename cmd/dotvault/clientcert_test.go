package main

import (
	"bytes"
	"context"
	"errors"
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
func (f forbiddenSigner) LookupSelf(context.Context) (*vaultapi.Secret, error) {
	f.t.Error("LookupSelf called")
	return nil, errors.New("forbidden")
}
func (f forbiddenSigner) SignCSR(context.Context, string, string, string, string, string) (*vault.IssuedCert, error) {
	f.t.Error("SignCSR called")
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
