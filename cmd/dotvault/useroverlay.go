package main

import (
	"fmt"
	"log/slog"
	"sync/atomic"

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
// The returned relax function switches the loader from strict to lenient, and
// the daemon calls it once startup has succeeded. The two postures exist
// because a broken user file means different things at the two moments:
//
//   - At startup it is the user's immediate mistake, and refusing to start
//     with a message naming the file is how they find out.
//   - On a refresh tick it must not be fatal to *everything else*. The
//     refresh loop treats a loader error as "reload failed" and gives up on
//     that pass, so a stray character in an unprivileged user's config.yaml
//     would otherwise stop the daemon converging on remote rules and
//     enrolments indefinitely — inverting the remote overlay's fail-open
//     ladder, for a static section that cannot apply live anyway. So the
//     overlay is dropped for that pass with a warning and policy still lands.
//
// A missing file is the common case and costs one failed stat.
func withUserOverlay(load func() (*config.Config, error)) (loader func() (*config.Config, error), relax func()) {
	var lenient atomic.Bool

	loader = func() (*config.Config, error) {
		cfg, err := load()
		if err != nil {
			return nil, err
		}
		if err := applyUserOverlay(cfg); err != nil {
			if !lenient.Load() {
				return nil, err
			}
			slog.Warn("ignoring the per-user configuration for this reload; policy still applied", "error", err)
			return cfg, nil
		}
		return cfg, nil
	}
	return loader, func() { lenient.Store(true) }
}

// applyUserOverlay merges the user's config.yaml over cfg in place.
//
// A user config that cannot be parsed or applied is an error naming the file,
// so someone told their configuration is wrong can open the thing that is
// wrong — on macOS and Windows it lives somewhere they would never guess. A
// path that cannot be *resolved* (no home directory) is not the user's mistake
// and only means there is no overlay to apply, so it warns and carries on.
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
	if err := cfg.ApplyUser(uc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if uc.FUSE != nil {
		// Provenance for `dotvault status`: this file contributed to the
		// section, so a mount that policy did not ask for can be explained.
		cfg.FUSE.UserOverlayPath = path
	}
	slog.Debug("applied per-user configuration preferences", "path", path)
	return nil
}
