package enrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"log/slog"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func sshTestIO(promptResponses ...string) IO {
	callIdx := 0
	return IO{
		Out:      &bytes.Buffer{},
		Log:      slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		Username: "testuser",
		PromptSecret: func(label string) (string, error) {
			if callIdx >= len(promptResponses) {
				return "", nil
			}
			resp := promptResponses[callIdx]
			callIdx++
			return resp, nil
		},
	}
}

func TestSSHEngine_Name(t *testing.T) {
	e := &SSHEngine{}
	if got := e.Name(); got != "SSH" {
		t.Errorf("Name() = %q, want %q", got, "SSH")
	}
}

func TestSSHEngine_Fields(t *testing.T) {
	e := &SSHEngine{}
	fields := e.Fields()
	if len(fields) != 2 {
		t.Fatalf("Fields() returned %d fields, want 2", len(fields))
	}
	if fields[0] != "public_key" || fields[1] != "private_key" {
		t.Errorf("Fields() = %v, want [public_key private_key]", fields)
	}
}

func TestSSHEngine_Unsafe_NoPassphrase(t *testing.T) {
	e := &SSHEngine{}
	io := sshTestIO() // no prompt responses needed
	settings := map[string]any{"passphrase": "unsafe"}

	creds, err := e.Run(context.Background(), settings, io)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// Check both fields present
	privPEM := creds["private_key"]
	pubKey := creds["public_key"]
	if privPEM == "" {
		t.Fatal("private_key is empty")
	}
	if pubKey == "" {
		t.Fatal("public_key is empty")
	}

	// Verify private key is valid OpenSSH PEM
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		t.Fatal("private_key is not valid PEM")
	}
	if block.Type != "OPENSSH PRIVATE KEY" {
		t.Errorf("PEM type = %q, want %q", block.Type, "OPENSSH PRIVATE KEY")
	}

	// Verify private key can be parsed without passphrase
	rawKey, err := ssh.ParseRawPrivateKey([]byte(privPEM))
	if err != nil {
		t.Fatalf("ParseRawPrivateKey() error: %v", err)
	}
	if _, ok := rawKey.(*ed25519.PrivateKey); !ok {
		t.Errorf("parsed key type = %T, want *ed25519.PrivateKey", rawKey)
	}

	// Verify public key format
	if !strings.HasPrefix(pubKey, "ssh-ed25519 ") {
		t.Errorf("public_key does not start with 'ssh-ed25519 ': %q", pubKey)
	}
	if !strings.HasSuffix(pubKey, " testuser@dotvault") {
		t.Errorf("public_key does not end with ' testuser@dotvault': %q", pubKey)
	}

	// Verify public key is parseable
	_, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey() error: %v", err)
	}
	if comment != "testuser@dotvault" {
		t.Errorf("comment = %q, want %q", comment, "testuser@dotvault")
	}
}

func TestSSHEngine_Required_WithPassphrase(t *testing.T) {
	e := &SSHEngine{}
	io := sshTestIO("hunter2", "hunter2") // two matching entries
	settings := map[string]any{"passphrase": "required"}

	creds, err := e.Run(context.Background(), settings, io)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	privPEM := creds["private_key"]

	// Verify the key cannot be parsed without passphrase
	_, err = ssh.ParseRawPrivateKey([]byte(privPEM))
	if err == nil {
		t.Fatal("expected error parsing encrypted key without passphrase")
	}

	// Verify the key can be parsed with the correct passphrase
	rawKey, err := ssh.ParseRawPrivateKeyWithPassphrase([]byte(privPEM), []byte("hunter2"))
	if err != nil {
		t.Fatalf("ParseRawPrivateKeyWithPassphrase() error: %v", err)
	}
	if _, ok := rawKey.(*ed25519.PrivateKey); !ok {
		t.Errorf("parsed key type = %T, want *ed25519.PrivateKey", rawKey)
	}
}

func TestSSHEngine_Required_EmptyPassphrase(t *testing.T) {
	e := &SSHEngine{}
	io := sshTestIO("", "") // empty entries
	settings := map[string]any{"passphrase": "required"}

	_, err := e.Run(context.Background(), settings, io)
	if err == nil {
		t.Fatal("expected error for empty passphrase in required mode")
	}
	if !strings.Contains(err.Error(), "passphrase is required") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "passphrase is required")
	}
}

func TestSSHEngine_Recommended_EmptyPassphrase(t *testing.T) {
	e := &SSHEngine{}
	io := sshTestIO("", "") // empty entries
	settings := map[string]any{"passphrase": "recommended"}

	creds, err := e.Run(context.Background(), settings, io)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// Should produce a valid unencrypted key
	privPEM := creds["private_key"]
	_, err = ssh.ParseRawPrivateKey([]byte(privPEM))
	if err != nil {
		t.Fatalf("key should be unencrypted but ParseRawPrivateKey() failed: %v", err)
	}
}

func TestSSHEngine_Mismatch(t *testing.T) {
	e := &SSHEngine{}
	io := sshTestIO("hunter2", "hunter3") // mismatched entries
	settings := map[string]any{"passphrase": "required"}

	_, err := e.Run(context.Background(), settings, io)
	if err == nil {
		t.Fatal("expected error for mismatched passphrases")
	}
	if !strings.Contains(err.Error(), "passphrases do not match") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "passphrases do not match")
	}
}

func TestSSHEngine_InvalidMode(t *testing.T) {
	e := &SSHEngine{}
	io := sshTestIO()
	settings := map[string]any{"passphrase": "bogus"}

	_, err := e.Run(context.Background(), settings, io)
	if err == nil {
		t.Fatal("expected error for invalid passphrase mode")
	}
	if !strings.Contains(err.Error(), "invalid passphrase mode") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "invalid passphrase mode")
	}
}

func TestSSHEngine_DefaultMode(t *testing.T) {
	e := &SSHEngine{}
	// No passphrase in settings — defaults to "required"
	io := sshTestIO("mypass", "mypass")
	settings := map[string]any{}

	creds, err := e.Run(context.Background(), settings, io)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// Key should be encrypted
	_, err = ssh.ParseRawPrivateKey([]byte(creds["private_key"]))
	if err == nil {
		t.Fatal("expected error parsing encrypted key without passphrase")
	}
	_, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(creds["private_key"]), []byte("mypass"))
	if err != nil {
		t.Fatalf("ParseRawPrivateKeyWithPassphrase() error: %v", err)
	}
}

