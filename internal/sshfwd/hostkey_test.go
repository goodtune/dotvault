package sshfwd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, s.PublicKey()
}

func addr(t *testing.T) net.Addr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", "192.0.2.1:22")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestHostKeyPolicyAcceptsPinnedKey(t *testing.T) {
	_, pub := testKey(t)
	p := HostKeyPolicy{Pinned: string(ssh.MarshalAuthorizedKey(pub))}
	if err := p.Callback(nil)("foo.example.com:22", addr(t), pub); err != nil {
		t.Fatalf("pinned key rejected: %v", err)
	}
}

func TestHostKeyPolicyRejectsChangedKey(t *testing.T) {
	_, pinned := testKey(t)
	_, other := testKey(t)
	p := HostKeyPolicy{Pinned: string(ssh.MarshalAuthorizedKey(pinned))}
	err := p.Callback(nil)("foo.example.com:22", addr(t), other)
	if err == nil {
		t.Fatal("changed host key accepted; must be rejected")
	}
	if errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("changed key reported as unknown, not mismatched: %v", err)
	}
}

func TestHostKeyPolicyRejectsUnknownAndReportsIt(t *testing.T) {
	_, pub := testKey(t)
	var seen ssh.PublicKey
	p := HostKeyPolicy{}
	err := p.Callback(&seen)("foo.example.com:22", addr(t), pub)
	if !errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("err = %v, want ErrHostKeyUnknown", err)
	}
	if seen == nil {
		t.Fatal("observed key not captured; `ssh add` cannot report a fingerprint")
	}
	if string(seen.Marshal()) != string(pub.Marshal()) {
		t.Error("observed key does not match the presented key")
	}
}

// hostCert builds a signed host certificate, defaulting to an infinite
// validity window and a single principal matching the dialled hostname; each
// field can be overridden by the case under test.
func hostCert(t *testing.T, caSigner ssh.Signer, opts ...func(*ssh.Certificate)) *ssh.Certificate {
	t.Helper()
	_, hostPub := testKey(t)
	cert := &ssh.Certificate{
		Key:             hostPub,
		CertType:        ssh.HostCert,
		KeyId:           "foo.example.com",
		ValidPrincipals: []string{"foo.example.com"},
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	for _, opt := range opts {
		opt(cert)
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestHostKeyPolicyAcceptsCASignedCert(t *testing.T) {
	caSigner, caPub := testKey(t)
	cert := hostCert(t, caSigner)

	caLine := "@cert-authority *.example.com " + string(ssh.MarshalAuthorizedKey(caPub))
	p := HostKeyPolicy{CAs: []string{caLine}}
	if err := p.Callback(nil)("foo.example.com:22", addr(t), cert); err != nil {
		t.Fatalf("CA-signed host cert rejected: %v", err)
	}
}

func TestHostKeyPolicyRejectsCertFromUnknownCA(t *testing.T) {
	otherCA, _ := testKey(t)
	_, knownCAPub := testKey(t)
	cert := hostCert(t, otherCA)

	caLine := "@cert-authority *.example.com " + string(ssh.MarshalAuthorizedKey(knownCAPub))
	p := HostKeyPolicy{CAs: []string{caLine}}
	err := p.Callback(nil)("foo.example.com:22", addr(t), cert)
	if err == nil {
		t.Fatal("cert from an unconfigured CA accepted; must be rejected")
	}
	if errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("cert from an unconfigured CA reported as unknown, not rejected: %v", err)
	}
}

// TestHostKeyPolicyRejectsUserCertAsHostCert pins the single most
// security-critical property of the certificate path, and it lives entirely
// in golang.org/x/crypto/ssh, not in this file: a user certificate — signed
// by the very same CA, for the very same host, with an otherwise-valid
// window and principal — must never be accepted as a host certificate. If a
// future dependency bump ever weakened that check, this is the test that
// would catch it.
func TestHostKeyPolicyRejectsUserCertAsHostCert(t *testing.T) {
	caSigner, caPub := testKey(t)
	cert := hostCert(t, caSigner, func(c *ssh.Certificate) { c.CertType = ssh.UserCert })

	caLine := "@cert-authority *.example.com " + string(ssh.MarshalAuthorizedKey(caPub))
	p := HostKeyPolicy{CAs: []string{caLine}}
	err := p.Callback(nil)("foo.example.com:22", addr(t), cert)
	if err == nil {
		t.Fatal("user certificate accepted as a host certificate; must be rejected")
	}
	if errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("user-cert-as-host-cert reported as unknown, not rejected: %v", err)
	}
}

func TestHostKeyPolicyRejectsExpiredCert(t *testing.T) {
	caSigner, caPub := testKey(t)
	past := uint64(time.Now().Add(-2 * time.Hour).Unix())
	expired := uint64(time.Now().Add(-1 * time.Hour).Unix())
	cert := hostCert(t, caSigner, func(c *ssh.Certificate) {
		c.ValidAfter = past
		c.ValidBefore = expired
	})

	caLine := "@cert-authority *.example.com " + string(ssh.MarshalAuthorizedKey(caPub))
	p := HostKeyPolicy{CAs: []string{caLine}}
	err := p.Callback(nil)("foo.example.com:22", addr(t), cert)
	if err == nil {
		t.Fatal("expired certificate accepted; must be rejected")
	}
	if errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("expired certificate reported as unknown, not rejected: %v", err)
	}
}

func TestHostKeyPolicyRejectsWrongPrincipalCert(t *testing.T) {
	caSigner, caPub := testKey(t)
	cert := hostCert(t, caSigner, func(c *ssh.Certificate) {
		c.ValidPrincipals = []string{"bar.example.com"}
	})

	caLine := "@cert-authority *.example.com " + string(ssh.MarshalAuthorizedKey(caPub))
	p := HostKeyPolicy{CAs: []string{caLine}}
	err := p.Callback(nil)("foo.example.com:22", addr(t), cert)
	if err == nil {
		t.Fatal("certificate for a different principal accepted; must be rejected")
	}
	if errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("wrong-principal certificate reported as unknown, not rejected: %v", err)
	}
}

func TestHostKeyPolicyRejectsCertWhenCAsLineIsNotACertAuthority(t *testing.T) {
	caSigner, caPub := testKey(t)
	cert := hostCert(t, caSigner)

	// A plain known_hosts line (no "@cert-authority" marker) for the same key
	// and pattern must not authorise the certificate — the marker, not just
	// the key, is what grants CA trust.
	plainLine := "*.example.com " + string(ssh.MarshalAuthorizedKey(caPub))
	p := HostKeyPolicy{CAs: []string{plainLine}}
	err := p.Callback(nil)("foo.example.com:22", addr(t), cert)
	if err == nil {
		t.Fatal("cert authorised by a non-@cert-authority line; marker must be required")
	}
	if errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("missing-marker rejection reported as unknown: %v", err)
	}
}

func TestHostKeyPolicyInsecureAcceptsAnything(t *testing.T) {
	_, pub := testKey(t)
	p := HostKeyPolicy{Insecure: true}
	if err := p.Callback(nil)("foo.example.com:22", addr(t), pub); err != nil {
		t.Fatalf("insecure policy rejected key: %v", err)
	}
}

// TestHostKeyPolicyInsecureLogsWarnEveryAttempt guards the entire
// justification for allowing insecure_ignore_host_key at all: the downgrade
// "cannot be set once and forgotten silently" (see
// internal/config.SSHConfig.InsecureIgnoreHostKey's doc comment). Deleting
// the slog.Warn call in Callback must fail this test.
func TestHostKeyPolicyInsecureLogsWarnEveryAttempt(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	_, pub := testKey(t)
	p := HostKeyPolicy{Insecure: true}
	cb := p.Callback(nil)

	if err := cb("foo.example.com:22", addr(t), pub); err != nil {
		t.Fatalf("insecure policy rejected key: %v", err)
	}
	if err := cb("bar.example.com:22", addr(t), pub); err != nil {
		t.Fatalf("insecure policy rejected key: %v", err)
	}

	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var warnCount int
	for _, line := range lines {
		if !strings.Contains(line, "level=WARN") {
			continue
		}
		warnCount++
		if !strings.Contains(line, "host=foo.example.com:22") && !strings.Contains(line, "host=bar.example.com:22") {
			t.Errorf("WARN record missing host attribute: %s", line)
		}
	}
	if warnCount != 2 {
		t.Fatalf("got %d WARN records for 2 insecure attempts, want 2:\n%s", warnCount, out)
	}
}
