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
func VaultTokenPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("USERPROFILE"), ".vault-token")
	default:
		return filepath.Join(mustHomeDir(), ".vault-token")
	}
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
	return home
}
