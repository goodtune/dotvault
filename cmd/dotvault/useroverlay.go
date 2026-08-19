package main

import (
	"log/slog"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
)

// userConfigPath is the resolver for the per-user preference overlay,
// injectable so tests can point it at a temp directory rather than the
// developer's real home.
var userConfigPath = paths.UserConfigPath

// withUserOverlay wraps a config loader with the per-user preference overlay:
// load (base ⊕ remote) → merge the user's own config.yaml → return.
//
// It wraps *outside* withRemote deliberately. The system configuration and any
// remote document together are policy, and the user's file expresses
// preference against that policy — so it has to be the last thing applied, or
// a remote refresh could quietly undo the user's choice on the next tick.
// (A remote document cannot carry `fuse` at all — partialStaticSections
// refuses it — so today the ordering is belt-and-braces rather than
// load-bearing, which is exactly when it is cheapest to get right.)
//
// The merge re-validates the section it touched, so an unparseable
// `cache_ttl` in the user's file is a startup error naming that file rather
// than a value that silently falls back to a default.
//
// A missing file is the common case and costs one failed stat.
func withUserOverlay(load func() (*config.Config, error)) func() (*config.Config, error) {
	return func() (*config.Config, error) {
		cfg, err := load()
		if err != nil {
			return nil, err
		}
		if err := applyUserOverlay(cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}
}

// applyUserOverlay merges the user's config.yaml over cfg in place.
//
// A user config that cannot be *parsed* is a hard error: the user wrote it
// deliberately, and starting with their preference silently discarded is
// worse than refusing to start with a message naming the file. A path that
// cannot be *resolved* (no home directory) is not the user's mistake and only
// means there is no overlay to apply, so it warns and carries on.
func applyUserOverlay(cfg *config.Config) error {
	path, err := userConfigPath()
	if err != nil {
		slog.Warn("could not resolve the user config path; per-user preferences not applied", "error", err)
		return nil
	}
	uc, err := config.LoadUserConfig(path)
	if err != nil {
		return err
	}
	if uc == nil {
		return nil
	}
	slog.Debug("applying per-user configuration preferences", "path", path)
	return cfg.ApplyUser(uc)
}
