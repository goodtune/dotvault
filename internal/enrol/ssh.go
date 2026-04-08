package enrol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHEngine generates Ed25519 SSH key pairs.
type SSHEngine struct{}

func (e *SSHEngine) Name() string     { return "SSH" }
func (e *SSHEngine) Fields() []string { return []string{"public_key", "private_key"} }

func (e *SSHEngine) Run(ctx context.Context, settings map[string]any, io IO) (map[string]string, error) {
	mode := "required"
	if v, ok := settings["passphrase"].(string); ok && v != "" {
		mode = v
	}

	passphrase, err := promptPassphrase(io, mode)
	if err != nil {
		return nil, err
	}

	comment := io.Username + "@dotvault"

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	// Marshal private key to OpenSSH PEM format.
	var pemBlock *pem.Block
	if passphrase != "" {
		pemBlock, err = ssh.MarshalPrivateKeyWithPassphrase(privKey, comment, []byte(passphrase))
	} else {
		pemBlock, err = ssh.MarshalPrivateKey(privKey, comment)
	}
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := string(pem.EncodeToMemory(pemBlock))

	// Marshal public key to authorized_keys format with comment.
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("create ssh public key: %w", err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + comment

	return map[string]string{
		"private_key": privPEM,
		"public_key":  pubLine,
	}, nil
}

func promptPassphrase(io IO, mode string) (string, error) {
	switch mode {
	case "unsafe":
		return "", nil
	case "required", "recommended":
		// handled below
	default:
		return "", fmt.Errorf("invalid passphrase mode: %q (must be required, recommended, or unsafe)", mode)
	}

	if io.PromptSecret == nil {
		return "", fmt.Errorf("passphrase prompt not available (PromptSecret is nil)")
	}

	first, err := io.PromptSecret("Enter passphrase:")
	if err != nil {
		return "", fmt.Errorf("passphrase prompt: %w", err)
	}

	if first == "" {
		if mode == "required" {
			return "", fmt.Errorf("passphrase is required")
		}
		// recommended: user opted out
		return "", nil
	}

	second, err := io.PromptSecret("Confirm passphrase:")
	if err != nil {
		return "", fmt.Errorf("passphrase confirm prompt: %w", err)
	}

	if first != second {
		return "", fmt.Errorf("passphrases do not match")
	}

	return first, nil
}
