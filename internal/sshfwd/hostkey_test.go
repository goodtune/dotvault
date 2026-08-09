package sshfwd

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"

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

func TestHostKeyPolicyAcceptsCASignedCert(t *testing.T) {
	caSigner, caPub := testKey(t)
	hostSigner, hostPub := testKey(t)

	cert := &ssh.Certificate{
		Key:             hostPub,
		CertType:        ssh.HostCert,
		KeyId:           "foo.example.com",
		ValidPrincipals: []string{"foo.example.com"},
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	_ = hostSigner

	caLine := "@cert-authority *.example.com " + string(ssh.MarshalAuthorizedKey(caPub))
	p := HostKeyPolicy{CAs: []string{caLine}}
	if err := p.Callback(nil)("foo.example.com:22", addr(t), cert); err != nil {
		t.Fatalf("CA-signed host cert rejected: %v", err)
	}
}

func TestHostKeyPolicyRejectsCertFromUnknownCA(t *testing.T) {
	otherCA, _ := testKey(t)
	_, knownCAPub := testKey(t)
	_, hostPub := testKey(t)

	cert := &ssh.Certificate{
		Key:             hostPub,
		CertType:        ssh.HostCert,
		KeyId:           "foo.example.com",
		ValidPrincipals: []string{"foo.example.com"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, otherCA); err != nil {
		t.Fatal(err)
	}

	caLine := "@cert-authority *.example.com " + string(ssh.MarshalAuthorizedKey(knownCAPub))
	p := HostKeyPolicy{CAs: []string{caLine}}
	if err := p.Callback(nil)("foo.example.com:22", addr(t), cert); err == nil {
		t.Fatal("cert from an unconfigured CA accepted; must be rejected")
	}
}

func TestHostKeyPolicyInsecureAcceptsAnything(t *testing.T) {
	_, pub := testKey(t)
	p := HostKeyPolicy{Insecure: true}
	if err := p.Callback(nil)("foo.example.com:22", addr(t), pub); err != nil {
		t.Fatalf("insecure policy rejected key: %v", err)
	}
}
