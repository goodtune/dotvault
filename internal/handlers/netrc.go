package handlers

import (
	"fmt"
	"os"

	"github.com/jdx/go-netrc"
)

// NetrcHandler handles .netrc files with per-entry merge.
type NetrcHandler struct{}

// NetrcCredential represents login+password for a machine.
type NetrcCredential struct {
	Login    string
	Password string
}

// NetrcVaultData maps machine names to credentials.
// This is the expected "incoming" type for Merge.
type NetrcVaultData map[string]NetrcCredential

func (h *NetrcHandler) Read(path string) (any, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return netrc.New(path), nil
		}
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	n, err := netrc.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("parse netrc %s: %w", path, err)
	}
	return n, nil
}

func (h *NetrcHandler) Merge(existing any, incoming any) (any, error) {
	n, ok := existing.(*netrc.Netrc)
	if !ok {
		return nil, fmt.Errorf("existing: expected *netrc.Netrc, got %T", existing)
	}
	vaultData, ok := incoming.(NetrcVaultData)
	if !ok {
		return nil, fmt.Errorf("incoming: expected NetrcVaultData, got %T", incoming)
	}

	for machine, cred := range vaultData {
		m := n.Machine(machine)
		if m != nil {
			// Update existing entry
			m.Set("login", cred.Login)
			m.Set("password", cred.Password)
		} else {
			// Add new entry
			n.AddMachine(machine, cred.Login, cred.Password)
		}
	}

	return n, nil
}

func (h *NetrcHandler) Write(path string, data any, perm os.FileMode) error {
	n, ok := data.(*netrc.Netrc)
	if !ok {
		return fmt.Errorf("expected *netrc.Netrc, got %T", data)
	}

	content := n.Render()
	return atomicWrite(path, []byte(content), perm)
}
