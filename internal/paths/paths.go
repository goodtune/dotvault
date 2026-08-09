package paths

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// SystemConfigPath returns the OS-appropriate path for the system config file.
func SystemConfigPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/dotvault/config.yaml"
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "dotvault", "config.yaml")
	default: // linux and others
		// Check XDG_CONFIG_DIRS first
		if dirs := os.Getenv("XDG_CONFIG_DIRS"); dirs != "" {
			for _, dir := range strings.Split(dirs, ":") {
				p := filepath.Join(dir, "dotvault", "config.yaml")
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
		return "/etc/xdg/dotvault/config.yaml"
	}
}

// CacheDir returns the OS-appropriate cache directory for dotvault.
func CacheDir() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(mustHomeDir(), "Library", "Caches", "dotvault")
	case "windows":
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "dotvault", "cache")
	default:
		return filepath.Join(mustHomeDir(), ".cache", "dotvault")
	}
}

// LogDir returns the OS-appropriate log directory for dotvault.
func LogDir() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(mustHomeDir(), "Library", "Logs", "dotvault")
	case "windows":
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "dotvault", "logs")
	default:
		return filepath.Join(mustHomeDir(), ".cache", "dotvault", "logs")
	}
}

// VaultTokenPath returns the path to the Vault token file.
//
// dotvault uses its own ~/.dotvault-token rather than Vault's default
// ~/.vault-token so a user running the upstream `vault` CLI in another
// context cannot clobber (or be clobbered by) the daemon's cached token.
//
// The home directory is resolved via os.UserHomeDir (mustHomeDir),
// using the OS's home-directory convention, and panics if it cannot be
// determined. Resolving an unset home as a panic — rather than joining
// onto an empty string and silently yielding a CWD-relative
// ".dotvault-token" — keeps a token from ever landing in the working
// directory. The panic is part of this function's documented contract;
// the client facade's DefaultTokenFile recovers it.
func VaultTokenPath() string {
	return filepath.Join(mustHomeDir(), ".dotvault-token")
}

// DefaultAgentSocket returns the per-user Unix domain socket path for the SSH
// agent when agent.unix.path is unset. It prefers the runtime dir
// ($XDG_RUNTIME_DIR/dotvault/agent.sock), which is owner-only and cleared on
// logout, and falls back to the cache dir dotvault already resolves when
// XDG_RUNTIME_DIR is empty (typical on macOS).
func DefaultAgentSocket() string {
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
		return filepath.Join(rt, "dotvault", "agent.sock")
	}
	return filepath.Join(CacheDir(), "agent.sock")
}

// DefaultAPISocket returns the per-user Unix domain socket path for the local
// API surface when api.unix.path is unset. It follows DefaultAgentSocket's
// resolution exactly — the runtime dir ($XDG_RUNTIME_DIR/dotvault/api.sock),
// which is owner-only and cleared on logout, falling back to the cache dir
// when XDG_RUNTIME_DIR is empty (typical on macOS).
//
// Both sides of the borrow resolve the path through this one function: the
// daemon binds it, and a client on the same machine derives the same value
// from the same config, so neither has to be told where the other put it.
//
// Note for service deployments: /run/user/<uid> is torn down when the user's
// last session ends unless lingering is enabled (`loginctl enable-linger`),
// which is exactly the disconnect the local socket exists to survive. The
// packaged systemd unit declares RuntimeDirectory=dotvault so the directory
// is owned by the unit; see docs/configuration/config-reference.md.
func DefaultAPISocket() string {
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
		return filepath.Join(rt, "dotvault", "api.sock")
	}
	return filepath.Join(CacheDir(), "api.sock")
}

// Username returns the current OS username with any domain prefix stripped.
func Username() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("get current user: %w", err)
	}
	name := u.Username
	// Strip domain prefix (e.g., DOMAIN\gary -> gary)
	if i := strings.LastIndex(name, "\\"); i >= 0 {
		name = name[i+1:]
	}
	return name, nil
}

// ExpandHome expands a leading ~ in a path to the user's home directory.
func ExpandHome(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	if path == "~" {
		return os.UserHomeDir()
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand home: %w", err)
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

// UserConfigDir returns the per-user configuration directory for dotvault.
//
// This is deliberately distinct from SystemConfigPath's directory. The system
// config is admin-owned (root on Linux, %ProgramData% on Windows, and on a GPO
// machine superseded entirely by HKLM policy), and dotvault deliberately does
// not read user-writable policy. Files here are the opposite: owned by the
// user, never consulted for policy, and never resolved from a system location.
//
// On Linux this is the same directory the packaged systemd unit already uses
// for its per-user EnvironmentFile (~/.config/dotvault/env).
func UserConfigDir() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		return filepath.Join(home, "Library", "Application Support", "dotvault"), nil
	case "windows":
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "dotvault"), nil
		}
		return "", fmt.Errorf("APPDATA is not set")
	default:
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return filepath.Join(xdg, "dotvault"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		return filepath.Join(home, ".config", "dotvault"), nil
	}
}

// SSHConfigPath returns the path to the user-level managed-SSH-forward
// configuration (ssh.yaml). It is a sibling of the per-user env file and is
// never resolved from a system location — see UserConfigDir.
func SSHConfigPath() (string, error) {
	dir, err := UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ssh.yaml"), nil
}

// ValidateLoopback checks that addr (host:port) resolves to a loopback address.
func ValidateLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Try resolving hostname
		addrs, err := net.LookupHost(host)
		if err != nil {
			return fmt.Errorf("cannot resolve %q: %w", host, err)
		}
		for _, a := range addrs {
			resolved := net.ParseIP(a)
			if resolved != nil && !resolved.IsLoopback() {
				return fmt.Errorf("address %q resolves to non-loopback %s", addr, a)
			}
		}
		return nil
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("address %q is not loopback", addr)
	}
	return nil
}

func mustHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(fmt.Sprintf("cannot determine home directory: %v", err))
	}
	// os.UserHomeDir only returns a value when the home env var is
	// non-empty (an empty $HOME / %USERPROFILE% surfaces as an error
	// above), so this should be unreachable. Guard it anyway: every
	// caller joins onto the result, and an empty home would silently
	// produce a CWD-relative path (e.g. a Vault token landing in the
	// working directory) instead of failing loudly.
	if home == "" {
		panic("cannot determine home directory: resolved to an empty path")
	}
	return home
}
