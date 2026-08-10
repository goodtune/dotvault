package sshfwd

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type fakeBackend struct {
	keys            []*sshagent.Key
	signer          ssh.Signer
	signErr         error
	signCall        int
	onSignWithFlags func(sshagent.SignatureFlags)
}

func (f *fakeBackend) List() ([]*sshagent.Key, error) { return f.keys, nil }

func (f *fakeBackend) SignWithFlags(key ssh.PublicKey, data []byte, flags sshagent.SignatureFlags) (*ssh.Signature, error) {
	f.signCall++
	if f.onSignWithFlags != nil {
		f.onSignWithFlags(flags)
	}
	if f.signErr != nil {
		return nil, f.signErr
	}
	return f.signer.Sign(rand.Reader, data)
}

func TestSignersWrapsEachBackendIdentity(t *testing.T) {
	s, pub := testKey(t)
	fb := &fakeBackend{
		keys:   []*sshagent.Key{{Format: pub.Type(), Blob: pub.Marshal(), Comment: "dotvault"}},
		signer: s,
	}

	signers, err := Signers(fb)
	if err != nil {
		t.Fatalf("Signers() = %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("Signers() returned %d, want 1", len(signers))
	}
	if string(signers[0].PublicKey().Marshal()) != string(pub.Marshal()) {
		t.Error("wrapped signer advertises the wrong public key")
	}

	sig, err := signers[0].Sign(rand.Reader, []byte("payload"))
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}
	if fb.signCall != 1 {
		t.Errorf("backend SignWithFlags called %d times, want 1 — signing must delegate, not use a local key", fb.signCall)
	}
	if err := pub.Verify([]byte("payload"), sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}
}

func TestSignersPropagatesSignError(t *testing.T) {
	s, pub := testKey(t)
	want := errors.New("vault unavailable")
	fb := &fakeBackend{
		keys:    []*sshagent.Key{{Format: pub.Type(), Blob: pub.Marshal()}},
		signer:  s,
		signErr: want,
	}
	signers, err := Signers(fb)
	if err != nil {
		t.Fatalf("Signers() = %v", err)
	}
	if _, err := signers[0].Sign(rand.Reader, []byte("x")); !errors.Is(err, want) {
		t.Fatalf("Sign() err = %v, want %v", err, want)
	}
}

func TestSignersOnEmptyBackend(t *testing.T) {
	signers, err := Signers(&fakeBackend{})
	if err != nil {
		t.Fatalf("Signers() = %v", err)
	}
	if len(signers) != 0 {
		t.Fatalf("Signers() returned %d, want 0", len(signers))
	}
}

// certKey creates a certificate-backed public key for testing SignWithAlgorithm.
func certKey(t *testing.T) (*ssh.Certificate, ssh.Signer) {
	t.Helper()
	s, pub := testKey(t)
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "test-cert",
		ValidPrincipals: []string{"testuser"},
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, s); err != nil {
		t.Fatal(err)
	}
	return cert, s
}

// TestSignWithAlgorithmCertificateIdentity verifies that SignWithAlgorithm
// correctly handles certificate-backed identities where the algorithm argument
// is the underlying (non-cert) algorithm name.
func TestSignWithAlgorithmCertificateIdentity(t *testing.T) {
	cert, signer := certKey(t)
	fb := &fakeBackend{
		keys:   []*sshagent.Key{{Format: cert.Type(), Blob: cert.Marshal(), Comment: "cert"}},
		signer: signer,
	}
	signers, err := Signers(fb)
	if err != nil {
		t.Fatalf("Signers() = %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}

	// Verify the signer is an AlgorithmSigner and call it with the underlying algorithm.
	algSigner, ok := signers[0].(ssh.AlgorithmSigner)
	if !ok {
		t.Fatalf("signer does not implement ssh.AlgorithmSigner")
	}

	// Call SignWithAlgorithm with the underlying algorithm (e.g. ssh-ed25519).
	// This is what x/crypto/ssh does when negotiating a certificate identity.
	sig, err := algSigner.SignWithAlgorithm(rand.Reader, []byte("payload"), cert.Key.Type())
	if err != nil {
		t.Fatalf("SignWithAlgorithm with underlying algorithm = %v", err)
	}

	// Verify the signature is valid against the underlying key.
	if err := cert.Key.Verify([]byte("payload"), sig); err != nil {
		t.Errorf("signature does not verify: %v", err)
	}

	// Verify the backend was called.
	if fb.signCall != 1 {
		t.Errorf("backend SignWithFlags called %d times, want 1", fb.signCall)
	}
}

// TestSignWithAlgorithmTableDriven tests SignWithAlgorithm against various inputs.
func TestSignWithAlgorithmTableDriven(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{
			name:      "empty string (caller has no preference)",
			algorithm: "",
			wantErr:   false,
		},
		{
			name:      "matching bare key type (ssh-ed25519)",
			algorithm: "ssh-ed25519",
			wantErr:   false,
		},
		{
			name:      "unsupported algorithm for ed25519 key",
			algorithm: "ecdsa-sha2-nistp256",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, pub := testKey(t)
			fb := &fakeBackend{
				keys:   []*sshagent.Key{{Format: pub.Type(), Blob: pub.Marshal(), Comment: "test"}},
				signer: s,
			}

			signers, err := Signers(fb)
			if err != nil {
				t.Fatalf("Signers() = %v", err)
			}

			algSigner := signers[0].(ssh.AlgorithmSigner)
			_, err = algSigner.SignWithAlgorithm(rand.Reader, []byte("payload"), tt.algorithm)

			if (err != nil) != tt.wantErr {
				t.Errorf("got err = %v, want error = %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil {
				var algoErr *ErrUnsupportedAlgorithm
				if !errors.As(err, &algoErr) {
					t.Errorf("expected ErrUnsupportedAlgorithm, got %T", err)
				}
			}
		})
	}
}

// TestSignWithAlgorithmHandshake verifies that a certificate-backed signer
// completes a real SSH handshake negotiation. This is the integration test
// that catches the algorithm-negotiation bug at its actual integration seam.
func TestSignWithAlgorithmHandshake(t *testing.T) {
	cert, certSigner := certKey(t)
	fb := &fakeBackend{
		keys:   []*sshagent.Key{{Format: cert.Type(), Blob: cert.Marshal(), Comment: "cert"}},
		signer: certSigner,
	}

	signers, err := Signers(fb)
	if err != nil {
		t.Fatalf("Signers() = %v", err)
	}

	// Create a separate server key for the SSH server.
	serverSigner, _ := testKey(t)

	// Set up a listener on localhost.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	// Start a minimal SSH server in a goroutine.
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		config := &ssh.ServerConfig{
			PublicKeyCallback: func(cm ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				// Accept any public key for this test.
				return &ssh.Permissions{}, nil
			},
		}
		config.AddHostKey(serverSigner)

		_, chans, reqs, err := ssh.NewServerConn(conn, config)
		if err != nil {
			done <- err
			return
		}

		// Discard requests and channels.
		go ssh.DiscardRequests(reqs)
		go func() {
			for range chans {
			}
		}()

		done <- nil
	}()

	// Dial the server as a client using the certificate-backed signer.
	clientConfig := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
				return signers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	addr := listener.Addr().String()
	conn, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		t.Fatalf("ssh.Dial failed: %v", err)
	}
	defer conn.Close()

	// Wait for server to finish.
	if err := <-done; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

// testRSAKey returns a real RSA signer. It is cached across tests because
// generating a 2048-bit key is the most expensive thing in this file, and
// every caller only needs *an* RSA key, not a distinct one.
//
// It exists because the RSA tests below used to build their "RSA" fixtures
// from testKey, which is hard-coded Ed25519 — so the only thing RSA about
// them was the flag constant, and the RSA-cert plus cert-stripping
// interaction they claim to cover was never exercised.
func testRSAKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	rsaKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			rsaKeyErr = err
			return
		}
		rsaSigner, rsaKeyErr = ssh.NewSignerFromKey(key)
	})
	if rsaKeyErr != nil {
		t.Fatal(rsaKeyErr)
	}
	return rsaSigner, rsaSigner.PublicKey()
}

var (
	rsaKeyOnce sync.Once
	rsaSigner  ssh.Signer
	rsaKeyErr  error
)

// rsaCertKey returns an RSA user certificate signed by its own RSA key.
func rsaCertKey(t *testing.T) (*ssh.Certificate, ssh.Signer) {
	t.Helper()
	s, pub := testRSAKey(t)
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "test-rsa-cert",
		ValidPrincipals: []string{"testuser"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, s); err != nil {
		t.Fatal(err)
	}
	return cert, s
}

// TestSignWithAlgorithmRSAFlags verifies that RSA signature algorithm flags
// are correctly mapped and passed to the backend, using a real RSA identity.
func TestSignWithAlgorithmRSAFlags(t *testing.T) {
	tests := []struct {
		name        string
		algorithm   string
		wantFlags   sshagent.SignatureFlags
		description string
	}{
		{
			name:        "rsa-sha2-256",
			algorithm:   ssh.KeyAlgoRSASHA256,
			wantFlags:   sshagent.SignatureFlagRsaSha256,
			description: "RSA with SHA256",
		},
		{
			name:        "rsa-sha2-512",
			algorithm:   ssh.KeyAlgoRSASHA512,
			wantFlags:   sshagent.SignatureFlagRsaSha512,
			description: "RSA with SHA512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, pub := testRSAKey(t)
			var capturedFlags sshagent.SignatureFlags

			fb := &fakeBackend{
				keys:   []*sshagent.Key{{Format: pub.Type(), Blob: pub.Marshal(), Comment: "test"}},
				signer: s,
				// Capture the flags passed to SignWithFlags
				onSignWithFlags: func(flags sshagent.SignatureFlags) {
					capturedFlags = flags
				},
			}

			signers, err := Signers(fb)
			if err != nil {
				t.Fatalf("Signers() = %v", err)
			}

			algSigner := signers[0].(ssh.AlgorithmSigner)
			_, err = algSigner.SignWithAlgorithm(rand.Reader, []byte("payload"), tt.algorithm)
			if err != nil {
				t.Fatalf("SignWithAlgorithm(%s) = %v", tt.algorithm, err)
			}

			if capturedFlags != tt.wantFlags {
				t.Errorf("backend received flags = %d, want %d (%s)", capturedFlags, tt.wantFlags, tt.description)
			}
		})
	}
}

// TestSignWithAlgorithmRSACertificateFlags verifies that a real RSA
// certificate with RSA flags works — the interaction between certificate
// type extraction and flag mapping, which is where an RSA identity behaves
// differently from an Ed25519 one.
func TestSignWithAlgorithmRSACertificateFlags(t *testing.T) {
	rsaCert, certSigner := rsaCertKey(t)

	var capturedFlags sshagent.SignatureFlags
	fb := &fakeBackend{
		keys:   []*sshagent.Key{{Format: rsaCert.Type(), Blob: rsaCert.Marshal(), Comment: "cert"}},
		signer: certSigner,
		onSignWithFlags: func(flags sshagent.SignatureFlags) {
			capturedFlags = flags
		},
	}

	signers, err := Signers(fb)
	if err != nil {
		t.Fatalf("Signers() = %v", err)
	}

	algSigner := signers[0].(ssh.AlgorithmSigner)

	// Test rsa-sha2-256 with certificate
	capturedFlags = 0
	_, err = algSigner.SignWithAlgorithm(rand.Reader, []byte("payload"), ssh.KeyAlgoRSASHA256)
	if err != nil {
		t.Fatalf("SignWithAlgorithm(rsa-sha2-256) = %v", err)
	}
	if capturedFlags != sshagent.SignatureFlagRsaSha256 {
		t.Errorf("rsa-sha2-256 cert: backend received flags = %d, want %d", capturedFlags, sshagent.SignatureFlagRsaSha256)
	}

	// Test rsa-sha2-512 with certificate
	capturedFlags = 0
	_, err = algSigner.SignWithAlgorithm(rand.Reader, []byte("payload"), ssh.KeyAlgoRSASHA512)
	if err != nil {
		t.Fatalf("SignWithAlgorithm(rsa-sha2-512) = %v", err)
	}
	if capturedFlags != sshagent.SignatureFlagRsaSha512 {
		t.Errorf("rsa-sha2-512 cert: backend received flags = %d, want %d", capturedFlags, sshagent.SignatureFlagRsaSha512)
	}

	// The cert-stripping half: x/crypto calls SignWithAlgorithm with the
	// underlying algorithm name, never the -cert-v01@openssh.com form, so
	// "ssh-rsa" must be accepted for an RSA certificate. Comparing against
	// the certificate's own Type() would reject it.
	capturedFlags = 0
	if _, err := algSigner.SignWithAlgorithm(rand.Reader, []byte("payload"), ssh.KeyAlgoRSA); err != nil {
		t.Fatalf("SignWithAlgorithm(ssh-rsa) on an RSA certificate = %v, want it accepted", err)
	}
	if capturedFlags != 0 {
		t.Errorf("ssh-rsa cert: backend received flags = %d, want 0 (no rsa-sha2 preference)", capturedFlags)
	}

	// And the negative: an algorithm that is neither a flag nor the
	// underlying key type is rejected, naming the underlying type.
	var unsupported *ErrUnsupportedAlgorithm
	_, err = algSigner.SignWithAlgorithm(rand.Reader, []byte("payload"), ssh.KeyAlgoED25519)
	if !errors.As(err, &unsupported) {
		t.Fatalf("SignWithAlgorithm(ssh-ed25519) on an RSA certificate = %v, want ErrUnsupportedAlgorithm", err)
	}
	if unsupported.keyType != ssh.KeyAlgoRSA {
		t.Errorf("rejection named key type %q, want %q (the certificate's underlying key)", unsupported.keyType, ssh.KeyAlgoRSA)
	}
}

// ErrUnsupportedAlgorithm is re-exported from identity.go for testing.
// (We can reference it directly here since it's defined in the same package.)
