package paths

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
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

// DefaultUpstreamAgentSocket returns the per-user Unix domain socket path used
// when an `agent` key source leaves its socket unset: the systemd user
// ssh-agent convention $XDG_RUNTIME_DIR/ssh-agent.socket, keeping the default
// in the same XDG runtime directory dotvault's own agent socket lives in.
// Returns "" when XDG_RUNTIME_DIR is unset (typical on macOS), so the caller
// can require an explicit path there rather than resolving a bare relative
// name.
func DefaultUpstreamAgentSocket() string {
	if rt := os.Getenv("XDG_RUNTIME_DIR"); rt != "" {
		return filepath.Join(rt, "ssh-agent.socket")
	}
	return ""
}

// UID returns the current user's numeric UID as a string (the account SID on
// Windows), for substitution into agent-endpoint templates. On Unix it uses the
// os.Getuid() syscall rather than os/user.Current(): the latter's pure-Go
// (CGO-disabled — dotvault's build) implementation reads /etc/passwd and errors
// when the running UID has no entry there, which is common in containers /
// distroless images; that would blank a {{.uid}} template and yield a bad path
// like "/run/user//ssh-agent.socket". The syscall always succeeds. Only Windows
// (where os.Getuid returns -1) falls back to os/user for the SID.
func UID() (string, error) {
	if runtime.GOOS != "windows" {
		return strconv.Itoa(os.Getuid()), nil
	}
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("get current user: %w", err)
	}
	return u.Uid, nil
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
