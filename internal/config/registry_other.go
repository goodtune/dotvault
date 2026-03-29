//go:build !windows

package config

// loadFromRegistry is a no-op on non-Windows platforms.
// It always returns (nil, false, nil) indicating no registry configuration
// is available, causing LoadSystem to fall back to file-based config.
func loadFromRegistry() (*Config, bool, error) {
	return nil, false, nil
}
