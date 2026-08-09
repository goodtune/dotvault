package main

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	gosync "sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/enrol"
	"github.com/goodtune/dotvault/internal/observability"
	"github.com/goodtune/dotvault/internal/sshfwd"
	"github.com/goodtune/dotvault/internal/sync"
)

// TestRunConfigRefreshAppliesRuleChanges drives the mode-agnostic refresh
// loop with a fake loader and observes the fan-out through the sync engine's
// state store: a rule set change must prune state entries for removed rules.
func TestRunConfigRefreshAppliesRuleChanges(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	initial := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{Name: "old", VaultKey: "old", Target: config.Target{Path: "/tmp/old", Format: "text"}},
		},
	}
	engine := sync.NewEngine(initial, nil, "user", statePath)
	engine.State().Set("old", sync.RuleState{VaultVersion: 1, LastSynced: time.Now()})

	updated := &config.Config{
		Vault: initial.Vault,
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{Name: "new", VaultKey: "new", Target: config.Target{Path: "/tmp/new", Format: "text"}},
		},
		Enrolments: map[string]config.Enrolment{"gh": {Engine: "github"}},
	}
	loader := func() (*config.Config, error) { return updated, nil }

	rm := enrol.NewRefreshManager(nil, "kv", "users/user/", initial.Enrolments, time.Minute)
	wm := enrol.NewWatchManager(nil, "kv", "users/user/", "user", initial.Enrolments, time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConfigRefresh(ctx, refreshDeps{
			load:           loader,
			interval:       10 * time.Millisecond,
			initial:        initial,
			initialStatic:  staticSectionsOf(initial),
			engine:         engine,
			refreshManager: rm,
			watchManager:   wm,
		})
	}()

	deadline := time.After(3 * time.Second)
	for {
		if _, ok := engine.State().Rules()["old"]; !ok {
			break
		}
		select {
		case <-deadline:
			t.Fatal("state entry for removed rule was never pruned by the refresh loop")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	<-done
}

// TestRunConfigRefreshManualReload drives the refresh loop with a ticker
// interval far beyond the test's lifetime and asserts that a manual reload
// request (the SIGHUP / tray path) runs a refresh pass immediately.
func TestRunConfigRefreshManualReload(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	initial := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{Name: "old", VaultKey: "old", Target: config.Target{Path: "/tmp/old", Format: "text"}},
		},
	}
	engine := sync.NewEngine(initial, nil, "user", statePath)
	engine.State().Set("old", sync.RuleState{VaultVersion: 1, LastSynced: time.Now()})

	updated := &config.Config{
		Vault: initial.Vault,
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{Name: "new", VaultKey: "new", Target: config.Target{Path: "/tmp/new", Format: "text"}},
		},
	}
	loader := func() (*config.Config, error) { return updated, nil }

	rm := enrol.NewRefreshManager(nil, "kv", "users/user/", initial.Enrolments, time.Minute)
	wm := enrol.NewWatchManager(nil, "kv", "users/user/", "user", initial.Enrolments, time.Minute)

	reloadCh := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConfigRefresh(ctx, refreshDeps{
			load:           loader,
			interval:       time.Hour, // never ticks within the test
			initial:        initial,
			initialStatic:  staticSectionsOf(initial),
			reload:         reloadCh,
			engine:         engine,
			refreshManager: rm,
			watchManager:   wm,
		})
	}()

	reloadCh <- struct{}{}

	deadline := time.After(3 * time.Second)
	for {
		if _, ok := engine.State().Rules()["old"]; !ok {
			break
		}
		select {
		case <-deadline:
			t.Fatal("manual reload request did not trigger an immediate refresh pass")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	<-done
}

// TestChangedStaticSections exercises the restart-required diff: each static
// section must be reported by its YAML name, dynamic sections must never
// appear, and observability header changes must be visible through the
// digest even though the snapshot does not retain the header values.
func TestChangedStaticSections(t *testing.T) {
	base := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Web:   config.WebConfig{Enabled: true, Listen: "127.0.0.1:9000"},
		Observability: config.ObservabilityConfig{
			Enabled:  true,
			Endpoint: "https://otel.example",
			Headers:  map[string]string{"Authorization": "Bearer s3cret"},
			Metrics:  config.ObservabilitySignalConfig{Headers: map[string]string{"X-Metrics-Key": "m3trics"}},
			Logs:     config.ObservabilitySignalConfig{Headers: map[string]string{"X-Logs-Key": "l0gs"}},
		},
		Rules: []config.Rule{
			{Name: "r", VaultKey: "k", Target: config.Target{Path: "/tmp/r", Format: "text"}},
		},
	}

	snap := staticSectionsOf(base)
	if snap.Observability.Headers != nil {
		t.Fatal("staticSectionsOf must not retain observability header values")
	}
	if snap.Observability.Metrics.Headers != nil || snap.Observability.Logs.Headers != nil {
		t.Fatal("staticSectionsOf must not retain the per-signal observability header values either")
	}
	if snap.HeadersDigest == ([32]byte{}) {
		t.Fatal("non-empty headers must produce a non-zero digest")
	}

	// Same static content, different dynamic content: no change reported.
	// remote_config is dynamic — the loader rebuilds the overlay fetcher
	// and the refresh loop re-derives its cadence — so it must not be
	// reported either.
	dynamicOnly := *base
	dynamicOnly.Sync = config.SyncConfig{Interval: time.Minute}
	dynamicOnly.Rules = nil
	dynamicOnly.RemoteConfig.URL = "https://config.example/doc"
	if got := changedStaticSections(snap, staticSectionsOf(&dynamicOnly)); len(got) != 0 {
		t.Errorf("dynamic-only change reported static sections: %v", got)
	}

	cases := []struct {
		name   string
		mutate func(*config.Config)
		want   string
	}{
		{"vault", func(c *config.Config) { c.Vault.Address = "https://other.example.com:8200" }, "vault"},
		{"web", func(c *config.Config) { c.Web.Listen = "127.0.0.1:9001" }, "web"},
		{"agent", func(c *config.Config) { c.Agent.Enabled = true }, "agent"},
		{"api", func(c *config.Config) { c.API.Enabled = true }, "api"},
		{"observability scalar", func(c *config.Config) { c.Observability.Endpoint = "https://elsewhere.example" }, "observability"},
		{"observability headers", func(c *config.Config) { c.Observability.Headers = map[string]string{"Authorization": "Bearer rotated"} }, "observability"},
		{"observability metrics headers", func(c *config.Config) {
			c.Observability.Metrics.Headers = map[string]string{"X-Metrics-Key": "rotated"}
		}, "observability"},
		{"observability logs headers", func(c *config.Config) {
			c.Observability.Logs.Headers = map[string]string{"X-Logs-Key": "rotated"}
		}, "observability"},
		{"bypass_system_config", func(c *config.Config) { c.BypassSystemConfig = true }, "bypass_system_config"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := *base
			// Copy the nested headers map so mutations don't alias base's.
			mutated.Observability.Headers = map[string]string{}
			for k, v := range base.Observability.Headers {
				mutated.Observability.Headers[k] = v
			}
			tc.mutate(&mutated)
			got := changedStaticSections(snap, staticSectionsOf(&mutated))
			if len(got) != 1 || got[0] != tc.want {
				t.Errorf("changedStaticSections = %v, want [%s]", got, tc.want)
			}
		})
	}
}

// TestDigestObservabilityHeadersDomainSeparation pins that the header digest
// distinguishes WHICH map a header lives in, not just the multiset of
// key/value pairs: moving a credential from the shared map to a per-signal
// map redirects which backend receives it, which is a real config change the
// restart-required diff must see.
func TestDigestObservabilityHeadersDomainSeparation(t *testing.T) {
	shared := config.ObservabilityConfig{
		Headers: map[string]string{"Authorization": "Bearer tok"},
	}
	moved := config.ObservabilityConfig{
		Metrics: config.ObservabilitySignalConfig{Headers: map[string]string{"Authorization": "Bearer tok"}},
	}
	if digestObservabilityHeaders(shared) == digestObservabilityHeaders(moved) {
		t.Error("moving a header from the shared map to metrics must change the digest")
	}

	metricsOnly := config.ObservabilityConfig{
		Metrics: config.ObservabilitySignalConfig{Headers: map[string]string{"Authorization": "Bearer tok"}},
	}
	logsOnly := config.ObservabilityConfig{
		Logs: config.ObservabilitySignalConfig{Headers: map[string]string{"Authorization": "Bearer tok"}},
	}
	if digestObservabilityHeaders(metricsOnly) == digestObservabilityHeaders(logsOnly) {
		t.Error("the same header under metrics vs logs must digest differently")
	}

	if digestObservabilityHeaders(shared) != digestObservabilityHeaders(shared) {
		t.Error("digest must be deterministic within a process")
	}
}

// TestWarnSharedHeadersToOverriddenEndpoint covers the cross-backend
// credential warning: it fires only for an enabled signal that redirects the
// endpoint while inheriting (nil) headers under a non-empty shared map, and
// an explicit per-signal headers map — empty included — silences it.
func TestWarnSharedHeadersToOverriddenEndpoint(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.ObservabilityConfig
		want bool
	}{
		{
			name: "overridden endpoint with inherited headers warns",
			cfg: config.ObservabilityConfig{
				Enabled:  true,
				Endpoint: "shared:4317",
				Headers:  map[string]string{"Authorization": "Bearer shared"},
				Logs:     config.ObservabilitySignalConfig{Endpoint: "logs.vendor.example:4317"},
			},
			want: true,
		},
		{
			name: "explicit empty per-signal headers silences",
			cfg: config.ObservabilityConfig{
				Enabled:  true,
				Endpoint: "shared:4317",
				Headers:  map[string]string{"Authorization": "Bearer shared"},
				Logs: config.ObservabilitySignalConfig{
					Endpoint: "logs.vendor.example:4317",
					Headers:  map[string]string{},
				},
			},
			want: false,
		},
		{
			name: "no shared headers, nothing to leak",
			cfg: config.ObservabilityConfig{
				Enabled:  true,
				Endpoint: "shared:4317",
				Logs:     config.ObservabilitySignalConfig{Endpoint: "logs.vendor.example:4317"},
			},
			want: false,
		},
		{
			name: "disabled signal cannot leak",
			cfg: config.ObservabilityConfig{
				Enabled:  true,
				Endpoint: "shared:4317",
				Headers:  map[string]string{"Authorization": "Bearer shared"},
				Logs: config.ObservabilitySignalConfig{
					Enabled:  boolPtrTest(false),
					Endpoint: "logs.vendor.example:4317",
				},
			},
			want: false,
		},
		{
			name: "same endpoint restated is not an override",
			cfg: config.ObservabilityConfig{
				Enabled:  true,
				Endpoint: "shared:4317",
				Headers:  map[string]string{"Authorization": "Bearer shared"},
				Metrics:  config.ObservabilitySignalConfig{Endpoint: "shared:4317"},
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logBuf := &syncBuffer{}
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(logBuf, nil)))
			t.Cleanup(func() { slog.SetDefault(prev) })

			warnSharedHeadersToOverriddenEndpoint(tc.cfg)

			got := strings.Contains(logBuf.String(), "inherits the shared headers")
			if got != tc.want {
				t.Errorf("warned = %v, want %v (log: %q)", got, tc.want, logBuf.String())
			}
			if strings.Contains(logBuf.String(), "Bearer shared") {
				t.Error("warning must never carry header values")
			}
		})
	}
}

func boolPtrTest(b bool) *bool { return &b }

// TestResolvedSignalLockstep guards the one lockstep pair with no other
// drift detection: config.ResolvedSignal and observability.Signal are
// deliberately separate structs (the observability package must not import
// config), bridged by a field-by-field copy in initObservability that
// compiles silently if a field is added on one side and forgotten on the
// other. Matching field-name sets won't catch a forgotten copy line, but
// they catch the far more likely failure of the structs themselves
// drifting.
func TestResolvedSignalLockstep(t *testing.T) {
	fieldNames := func(v any) map[string]bool {
		names := map[string]bool{}
		typ := reflect.TypeOf(v)
		for i := 0; i < typ.NumField(); i++ {
			names[typ.Field(i).Name] = true
		}
		return names
	}
	resolved := fieldNames(config.ResolvedSignal{})
	signal := fieldNames(observability.Signal{})
	for name := range resolved {
		if !signal[name] {
			t.Errorf("config.ResolvedSignal.%s has no observability.Signal counterpart; add it (and the copy in initObservability) or record the exception here", name)
		}
	}
	for name := range signal {
		if !resolved[name] {
			t.Errorf("observability.Signal.%s has no config.ResolvedSignal counterpart; add it (and the copy in initObservability) or record the exception here", name)
		}
	}
}

// TestWarnDeprecatedObservabilityConfig covers the stage-one deprecation
// gate: the WARN fires only when the master switch is on AND a shared
// exporter field is in use, names every field in one line, stays silent for
// the per-signal migration target, and returns exactly the fields the
// caller must meter once the real provider is up.
func TestWarnDeprecatedObservabilityConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.ObservabilityConfig
		want []string
	}{
		{
			name: "shared fields under enabled master warn",
			cfg: config.ObservabilityConfig{
				Enabled:  true,
				Endpoint: "shared:4317",
				Headers:  map[string]string{"Authorization": "Bearer x"},
			},
			want: []string{"observability.endpoint", "observability.headers"},
		},
		{
			name: "disabled master is silent even with shared fields",
			cfg: config.ObservabilityConfig{
				Endpoint: "shared:4317",
			},
			want: nil,
		},
		{
			name: "per-signal-only config is silent",
			cfg: config.ObservabilityConfig{
				Enabled: true,
				Metrics: config.ObservabilitySignalConfig{Endpoint: "metrics:4317"},
			},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logBuf := &syncBuffer{}
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(logBuf, nil)))
			t.Cleanup(func() { slog.SetDefault(prev) })

			got := warnDeprecatedObservabilityConfig(tc.cfg)

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("returned fields = %v, want %v", got, tc.want)
			}
			warned := strings.Contains(logBuf.String(), "deprecated shared observability fields")
			if warned != (tc.want != nil) {
				t.Errorf("warned = %v, want %v (log: %q)", warned, tc.want != nil, logBuf.String())
			}
			if tc.want != nil && !strings.Contains(logBuf.String(), "observability.endpoint") {
				t.Error("warning must name the deprecated fields")
			}
			if strings.Contains(logBuf.String(), "Bearer x") {
				t.Error("warning must never carry header values")
			}
		})
	}
}

// TestStaticSectionsCoverConfig guards the static/dynamic split against
// drift: every top-level config.Config field must be explicitly classified
// here. A section added to config.Config without a decision fails this test
// instead of silently being neither applied on reload nor named in the
// restart-required warning.
func TestStaticSectionsCoverConfig(t *testing.T) {
	classified := map[string]string{
		"Vault":              "static",
		"Sync":               "dynamic", // sync.interval applies in place on reload
		"Web":                "static",
		"Observability":      "static",
		"Agent":              "static",
		"API":                "static",  // the socket listener is bound once at startup
		"RemoteConfig":       "dynamic", // fetcher rebuilt by the loader, cadence re-derived by the loop
		"Rules":              "dynamic",
		"Enrolments":         "dynamic",
		"SSH":                "dynamic", // certificate_authorities/insecure_ignore_host_key applied via updateSSHPolicyConfig's atomic value
		"BypassSystemConfig": "static",
		"Managed":            "derived", // set by the loader from the config source, not a section
	}
	typ := reflect.TypeOf(config.Config{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if _, ok := classified[name]; !ok {
			t.Errorf("config.Config field %q is not classified as static or dynamic; decide, then update staticSectionsOf/changedStaticSections (cmd/dotvault/main.go) or the refresh loop's dynamic fan-out, and record the decision here", name)
		}
	}
	for name := range classified {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("classified field %q no longer exists on config.Config; prune it from this test", name)
		}
	}
}

// syncBuffer is a goroutine-safe bytes.Buffer for capturing slog output from
// the refresh-loop goroutine.
type syncBuffer struct {
	mu  gosync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestRunConfigRefreshStaticChangeWarns drives the loop through a static
// config change, a repeat of the same change, and a revert, asserting the
// restart-required warning fires exactly once per edit and that reverting to
// the running configuration produces the all-clear rather than a second
// (false) restart-required warning.
func TestRunConfigRefreshStaticChangeWarns(t *testing.T) {
	logBuf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logBuf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	statePath := filepath.Join(t.TempDir(), "state.json")
	initial := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{Name: "r", VaultKey: "k", Target: config.Target{Path: "/tmp/r", Format: "text"}},
		},
	}
	edited := *initial
	edited.Vault.Address = "https://other.example.com:8200"

	var current atomic.Pointer[config.Config]
	current.Store(&edited)
	loader := func() (*config.Config, error) { return current.Load(), nil }

	engine := sync.NewEngine(initial, nil, "user", statePath)
	rm := enrol.NewRefreshManager(nil, "kv", "users/user/", nil, time.Minute)
	wm := enrol.NewWatchManager(nil, "kv", "users/user/", "user", nil, time.Minute)

	// Unbuffered on purpose: each send returns only once the loop has
	// received it, i.e. once the previous refresh pass fully completed and
	// the loop is back at its select. That makes the log assertions below
	// race-free without polling.
	reloadCh := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConfigRefresh(ctx, refreshDeps{
			load:           loader,
			interval:       time.Hour, // never ticks within the test
			initial:        initial,
			initialStatic:  staticSectionsOf(initial),
			reload:         reloadCh,
			engine:         engine,
			refreshManager: rm,
			watchManager:   wm,
		})
	}()

	reloadCh <- struct{}{} // pass 1: static change -> warn
	reloadCh <- struct{}{} // pass 2: same content -> deduplicated, no second warn
	current.Store(initial)
	reloadCh <- struct{}{} // pass 3: reverted -> all-clear, no restart-required warn
	reloadCh <- struct{}{} // pass 4: barrier so pass 3's logging is complete
	cancel()
	<-done

	logs := logBuf.String()
	if got := strings.Count(logs, "restart the daemon to apply them"); got != 1 {
		t.Errorf("restart-required warning logged %d times, want exactly 1\nlogs:\n%s", got, logs)
	}
	if !strings.Contains(logs, "sections=vault") {
		t.Errorf("restart-required warning does not name the changed section\nlogs:\n%s", logs)
	}
	if !strings.Contains(logs, "restart no longer needed") {
		t.Errorf("revert to the running configuration did not log the all-clear\nlogs:\n%s", logs)
	}
}

// TestRunConfigRefreshCadenceFollowsReload pins remote_config's dynamic
// classification: a reloaded remote_config.refresh_interval must retune the
// loop's own ticker. The loop starts with an effectively-infinite cadence, a
// manual nudge delivers a config carrying a fast refresh_interval, and then
// — with no further nudges — a subsequent config change must be picked up by
// the retuned ticker alone.
func TestRunConfigRefreshCadenceFollowsReload(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	initial := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		Rules: []config.Rule{
			{Name: "old", VaultKey: "old", Target: config.Target{Path: "/tmp/old", Format: "text"}},
		},
	}
	engine := sync.NewEngine(initial, nil, "user", statePath)
	engine.State().Set("old", sync.RuleState{VaultVersion: 1, LastSynced: time.Now()})

	// Same rules as initial, but a fast refresh cadence.
	retuned := *initial
	retuned.RemoteConfig.RefreshInterval = 10 * time.Millisecond

	// Different rules; only reachable once the retuned ticker fires.
	swapped := retuned
	swapped.Rules = []config.Rule{
		{Name: "new", VaultKey: "new", Target: config.Target{Path: "/tmp/new", Format: "text"}},
	}

	var current atomic.Pointer[config.Config]
	current.Store(&retuned)
	loader := func() (*config.Config, error) { return current.Load(), nil }

	rm := enrol.NewRefreshManager(nil, "kv", "users/user/", nil, time.Minute)
	wm := enrol.NewWatchManager(nil, "kv", "users/user/", "user", nil, time.Minute)

	reloadCh := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConfigRefresh(ctx, refreshDeps{
			load:           loader,
			interval:       time.Hour, // start effectively tickless
			initial:        initial,
			initialStatic:  staticSectionsOf(initial),
			reload:         reloadCh,
			engine:         engine,
			refreshManager: rm,
			watchManager:   wm,
		})
	}()

	reloadCh <- struct{}{} // applies the 10ms cadence
	current.Store(&swapped)

	// No further nudges: only the retuned ticker can deliver this.
	deadline := time.After(3 * time.Second)
	for {
		if _, ok := engine.State().Rules()["old"]; !ok {
			break
		}
		select {
		case <-deadline:
			t.Fatal("reloaded remote_config.refresh_interval did not retune the refresh ticker")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	<-done
}

// TestRunConfigRefreshAppliesSSHConfigDynamically proves the SSH section's
// "dynamic" classification (see TestStaticSectionsCoverConfig) is actually
// implemented, not merely asserted: a reloaded certificate_authorities list
// must reach a HostKeyPolicy built *after* the reload, via
// updateSSHPolicyConfig's atomic value, with no daemon restart.
func TestRunConfigRefreshAppliesSSHConfigDynamically(t *testing.T) {
	oldCA := "@cert-authority * ssh-ed25519 AAAAOLD old-ca"
	newCA := "@cert-authority * ssh-ed25519 AAAANEW new-ca"

	// Isolate this test from sshPolicyConfig's package-level state.
	updateSSHPolicyConfig(config.SSHConfig{CertificateAuthorities: []string{oldCA}})
	t.Cleanup(func() { updateSSHPolicyConfig(config.SSHConfig{}) })

	statePath := filepath.Join(t.TempDir(), "state.json")
	initial := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
		SSH:   config.SSHConfig{CertificateAuthorities: []string{oldCA}},
	}

	edited := *initial
	edited.SSH = config.SSHConfig{CertificateAuthorities: []string{newCA}}

	var current atomic.Pointer[config.Config]
	current.Store(initial)
	loader := func() (*config.Config, error) { return current.Load(), nil }

	engine := sync.NewEngine(initial, nil, "user", statePath)
	rm := enrol.NewRefreshManager(nil, "kv", "users/user/", nil, time.Minute)
	wm := enrol.NewWatchManager(nil, "kv", "users/user/", "user", nil, time.Minute)

	sshMgr := sshfwd.NewManager(sshfwd.Deps{})
	t.Cleanup(sshMgr.Close)
	sshConfigPath := filepath.Join(t.TempDir(), "ssh.yaml")
	sshRegistry := sshfwd.NewRegistry(sshConfigPath, sshMgr, nil)

	// Built once, before the daemon has ever seen the edited config —
	// exactly the daemon's real situation: sshForwardDeps runs once at
	// startup, and the Policy closure it returns is the one thing that
	// must go on reading live state afterwards. Asserting against *this*
	// object (rather than building a fresh one from the edited config, as
	// an earlier version of this test did) is what makes the test fail if
	// Policy is ever changed to read its captured cfg parameter instead of
	// currentSSHPolicyConfig() — see the capture-mutation check in the
	// task report.
	deps, err := sshForwardDeps(&config.Config{
		Web:   config.WebConfig{Enabled: true, Listen: "127.0.0.1:9000"},
		Agent: config.AgentConfig{Enabled: true},
		SSH:   initial.SSH,
	}, fakeSignerSource{}, "user")
	if err != nil {
		t.Fatalf("sshForwardDeps: %v", err)
	}

	reloadCh := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConfigRefresh(ctx, refreshDeps{
			load:           loader,
			interval:       time.Hour,
			initial:        initial,
			initialStatic:  staticSectionsOf(initial),
			reload:         reloadCh,
			engine:         engine,
			refreshManager: rm,
			watchManager:   wm,
			sshRegistry:    sshRegistry,
		})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	if got := deps.Policy(sshfwd.Remote{Host: "example.com"}).CAs; len(got) != 1 || got[0] != oldCA {
		t.Fatalf("before any reload, deps.Policy(...).CAs = %v, want [%q]", got, oldCA)
	}

	current.Store(&edited)
	reloadCh <- struct{}{}

	deadline := time.After(2 * time.Second)
	for {
		if got := deps.Policy(sshfwd.Remote{Host: "example.com"}).CAs; len(got) == 1 && got[0] == newCA {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("reloaded SSH config section was not applied to the pre-existing Deps.Policy; got = %v, want [%q]",
				deps.Policy(sshfwd.Remote{Host: "example.com"}).CAs, newCA)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestRunConfigRefreshReconcilesSSHYAMLOnHandEdit proves the stated
// hand-edit-converges-without-restart requirement: editing ssh.yaml directly
// (as a human, bypassing the Registry/web API entirely) must be picked up by
// the next refresh pass.
func TestRunConfigRefreshReconcilesSSHYAMLOnHandEdit(t *testing.T) {
	sshConfigPath := filepath.Join(t.TempDir(), "ssh.yaml")

	sshMgr := sshfwd.NewManager(sshfwd.Deps{})
	t.Cleanup(sshMgr.Close)
	sshRegistry := sshfwd.NewRegistry(sshConfigPath, sshMgr, nil)

	statePath := filepath.Join(t.TempDir(), "state.json")
	initial := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
	}
	loader := func() (*config.Config, error) { c := *initial; return &c, nil }

	engine := sync.NewEngine(initial, nil, "user", statePath)
	rm := enrol.NewRefreshManager(nil, "kv", "users/user/", nil, time.Minute)
	wm := enrol.NewWatchManager(nil, "kv", "users/user/", "user", nil, time.Minute)

	reloadCh := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConfigRefresh(ctx, refreshDeps{
			load:           loader,
			interval:       time.Hour,
			initial:        initial,
			initialStatic:  staticSectionsOf(initial),
			reload:         reloadCh,
			engine:         engine,
			refreshManager: rm,
			watchManager:   wm,
			sshRegistry:    sshRegistry,
		})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	reloadCh <- struct{}{} // pass 1: no ssh.yaml yet -> zero remotes
	if got := sshMgr.Status(); len(got) != 0 {
		t.Fatalf("Status = %v, want empty before ssh.yaml exists", got)
	}

	// Hand-edit ssh.yaml directly, the way a human editing the file (or an
	// older `dotvault ssh add` run against a stopped daemon) would — not
	// through the Registry.
	f := &sshfwd.File{Remotes: []sshfwd.Remote{{Host: "example.com", RemoteSocket: sshfwd.DefaultRemoteSocket}}}
	if err := sshfwd.Save(sshConfigPath, f); err != nil {
		t.Fatal(err)
	}

	reloadCh <- struct{}{} // pass 2: should pick up the new remote

	deadline := time.After(2 * time.Second)
	for {
		st := sshMgr.Status()
		if len(st) == 1 && st[0].Host == "example.com" {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("hand-edited ssh.yaml was not reconciled into the running manager; status=%v", st)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// TestRunConfigRefreshSSHResyncSerializedAgainstRegistryMutation proves the
// fix for the file-vs-running-set consistency gap: the refresh loop's
// ssh.yaml pickup goes through Registry.Resync, which holds the same write
// lock Registry.Add/Patch/Remove hold across their own Load->Save->Reconcile
// — so a concurrent removal can never be raced-and-reverted by a refresh
// pass that read the file a moment earlier.
//
// It uses Registry.SetResyncDelayForTest to force the interleaving that
// would otherwise depend on getting unlucky with real goroutine scheduling:
// the hook fires from inside Resync, after ssh.yaml has been read but before
// the Manager is reconciled, still holding the write lock. While the refresh
// loop's Resync call sits paused there, a concurrent Registry.Remove must
// block until the lock is released — proving mutual exclusion, not just
// most-of-the-time correctness — and the manager's final state must reflect
// the removal.
//
// This test is meaningless against code that bypasses Registry.Resync (the
// pre-fix shape: a direct sshfwd.Load + Manager.Reconcile in the refresh
// loop) — that code never calls the hook, so it hangs waiting for
// pausedInResync rather than silently passing; the deadline below turns that
// into a clean failure instead of a hung test.
func TestRunConfigRefreshSSHResyncSerializedAgainstRegistryMutation(t *testing.T) {
	sshConfigPath := filepath.Join(t.TempDir(), "ssh.yaml")

	sshMgr := sshfwd.NewManager(sshfwd.Deps{})
	t.Cleanup(sshMgr.Close)
	sshRegistry := sshfwd.NewRegistry(sshConfigPath, sshMgr, nil)

	// Seed remote A. Force skips verification (no Verifier is wired above).
	if _, err := sshRegistry.Add(context.Background(),
		sshfwd.Remote{Host: "a.example.com", RemoteSocket: sshfwd.DefaultRemoteSocket},
		sshfwd.AddOptions{Force: true},
	); err != nil {
		t.Fatalf("seed Add: %v", err)
	}
	if got := sshMgr.Status(); len(got) != 1 {
		t.Fatalf("Status = %v, want 1 remote after seeding", got)
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	initial := &config.Config{
		Vault: config.VaultConfig{Address: "https://vault.example.com:8200", UserPrefix: "users/"},
		Sync:  config.SyncConfig{Interval: time.Hour},
	}
	loader := func() (*config.Config, error) { c := *initial; return &c, nil }

	engine := sync.NewEngine(initial, nil, "user", statePath)
	rm := enrol.NewRefreshManager(nil, "kv", "users/user/", nil, time.Minute)
	wm := enrol.NewWatchManager(nil, "kv", "users/user/", "user", nil, time.Minute)

	pausedInResync := make(chan struct{})
	resumeResync := make(chan struct{})
	sshRegistry.SetResyncDelayForTest(func() {
		close(pausedInResync)
		<-resumeResync
	})

	reloadCh := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runConfigRefresh(ctx, refreshDeps{
			load:           loader,
			interval:       time.Hour,
			initial:        initial,
			initialStatic:  staticSectionsOf(initial),
			reload:         reloadCh,
			engine:         engine,
			refreshManager: rm,
			watchManager:   wm,
			sshRegistry:    sshRegistry,
		})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	// Trigger the refresh pass whose Resync call will pause inside the hook.
	go func() { reloadCh <- struct{}{} }()

	select {
	case <-pausedInResync:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh pass never reached Registry.Resync's paused hook — the loop is not calling Resync")
	}

	// While Resync holds the write lock, a concurrent Remove must block
	// rather than complete.
	removeDone := make(chan struct{})
	go func() {
		_, _ = sshRegistry.Remove(context.Background(), "a.example.com")
		close(removeDone)
	}()

	select {
	case <-removeDone:
		t.Fatal("Remove completed while Resync held the write lock — the two are not serialized")
	case <-time.After(100 * time.Millisecond):
	}

	close(resumeResync)

	select {
	case <-removeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Remove did not complete after Resync released the write lock")
	}

	if got := sshMgr.Status(); len(got) != 0 {
		t.Fatalf("Status = %v, want empty — the removal must not be reverted by the concurrently-paused refresh pass", got)
	}
}
