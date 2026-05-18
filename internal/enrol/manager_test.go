package enrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
)

// testPrefix returns a per-test unique Vault prefix so tests are
// idempotent against a long-lived dev server.
func testPrefix(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test/%s/", t.Name())
}

// enableKVv2 enables a KV v2 mount, ignoring "already in use" errors.
func enableKVv2(t *testing.T, vc *vault.Client, mount string) {
	t.Helper()
	ctx := context.Background()
	if err := vc.EnableKVv2(ctx, mount); err != nil && !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("EnableKVv2(%q): %v", mount, err)
	}
}

// seedKVv2 writes a secret, failing the test on error.
func seedKVv2(t *testing.T, vc *vault.Client, mount, path string, data map[string]any) {
	t.Helper()
	ctx := context.Background()
	if err := vc.WriteKVv2(ctx, mount, path, data); err != nil {
		t.Fatalf("WriteKVv2(%q, %q): %v", mount, path, err)
	}
}

// mockEngine is an Engine for testing.
type mockEngine struct {
	name   string
	fields []string
	creds  map[string]string
	err    error
	called int
}

func (e *mockEngine) Name() string     { return e.name }
func (e *mockEngine) Fields() []string { return e.fields }
func (e *mockEngine) Run(_ context.Context, _ map[string]any, _ IO) (map[string]string, error) {
	e.called++
	return e.creds, e.err
}

func testIO(buf *bytes.Buffer) IO {
	return IO{
		Out:      buf,
		Browser:  func(url string) error { return nil },
		Log:      slog.New(slog.NewTextHandler(buf, nil)),
		Username: "testuser",
	}
}

func skipIfNoVault(t *testing.T) *vault.Client {
	t.Helper()
	vc, err := vault.NewClient(vault.Config{
		Address: "http://127.0.0.1:8200",
		Token:   "dev-root-token",
	})
	if err != nil {
		t.Skip("vault not available")
	}
	ctx := context.Background()
	if _, err := vc.LookupSelf(ctx); err != nil {
		t.Skip("vault not available")
	}
	return vc
}

func TestCheckAll_AllPresent(t *testing.T) {
	vc := skipIfNoVault(t)
	ctx := context.Background()

	eng := &mockEngine{name: "test", fields: []string{"token"}, creds: map[string]string{"token": "abc"}}
	RegisterEngine("test-present", eng)
	t.Cleanup(func() { UnregisterEngine("test-present") })

	// Pre-seed vault with complete credentials
	enableKVv2(t, vc, "kv")
	prefix := testPrefix(t)
	seedKVv2(t, vc, "kv", prefix+"mykey", map[string]any{"token": "existing"})

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"mykey": {Engine: "test-present"},
		},
		KVMount:    "kv",
		UserPrefix: prefix,
	}, vc, testIO(&buf))

	enrolled, err := mgr.CheckAll(ctx)
	if err != nil {
		t.Fatalf("CheckAll() error: %v", err)
	}
	if enrolled {
		t.Error("enrolled=true, want false — secrets already present")
	}
	if eng.called != 0 {
		t.Errorf("engine called %d times, want 0", eng.called)
	}
}

func TestCheckAll_Missing(t *testing.T) {
	vc := skipIfNoVault(t)
	ctx := context.Background()

	eng := &mockEngine{name: "test", fields: []string{"token"}, creds: map[string]string{"token": "newtoken"}}
	RegisterEngine("test-missing", eng)
	t.Cleanup(func() { UnregisterEngine("test-missing") })

	enableKVv2(t, vc, "kv")
	prefix := testPrefix(t)

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"newkey": {Engine: "test-missing"},
		},
		KVMount:    "kv",
		UserPrefix: prefix,
	}, vc, testIO(&buf))

	enrolled, err := mgr.CheckAll(ctx)
	if err != nil {
		t.Fatalf("CheckAll() error: %v", err)
	}
	if !enrolled {
		t.Error("enrolled=false, want true — new secret should have been written")
	}
	if eng.called != 1 {
		t.Errorf("engine called %d times, want 1", eng.called)
	}

	// Verify vault was written
	secret, err := vc.ReadKVv2(ctx, "kv", prefix+"newkey")
	if err != nil {
		t.Fatalf("ReadKVv2 error: %v", err)
	}
	if secret == nil {
		t.Fatal("expected secret in vault, got nil")
	}
	if secret.Data["token"] != "newtoken" {
		t.Errorf("vault token = %v, want %q", secret.Data["token"], "newtoken")
	}
}

func TestCheckAll_PartialFailure(t *testing.T) {
	vc := skipIfNoVault(t)
	ctx := context.Background()

	engOK := &mockEngine{name: "ok", fields: []string{"x"}, creds: map[string]string{"x": "val"}}
	engFail := &mockEngine{name: "fail", fields: []string{"y"}, err: fmt.Errorf("auth denied")}
	RegisterEngine("test-ok", engOK)
	RegisterEngine("test-fail", engFail)
	t.Cleanup(func() {
		UnregisterEngine("test-ok")
		UnregisterEngine("test-fail")
	})

	enableKVv2(t, vc, "kv")
	prefix := testPrefix(t)

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"keyok":   {Engine: "test-ok"},
			"keyfail": {Engine: "test-fail"},
		},
		KVMount:    "kv",
		UserPrefix: prefix,
	}, vc, testIO(&buf))

	enrolled, err := mgr.CheckAll(ctx)
	if err != nil {
		t.Fatalf("CheckAll() error: %v", err)
	}
	if !enrolled {
		t.Error("enrolled=false, want true — at least one should succeed")
	}

	// ok key should be in vault
	secret, err := vc.ReadKVv2(ctx, "kv", prefix+"keyok")
	if err != nil {
		t.Fatalf("ReadKVv2() error for keyok: %v", err)
	}
	if secret == nil {
		t.Error("expected keyok in vault")
	}
	// fail key should not be in vault
	secret, err = vc.ReadKVv2(ctx, "kv", prefix+"keyfail")
	if err != nil {
		t.Fatalf("ReadKVv2() error for keyfail: %v", err)
	}
	if secret != nil {
		t.Error("keyfail should not be in vault after failure")
	}
}

func TestCheckAll_UnknownEngine(t *testing.T) {
	vc := skipIfNoVault(t)
	ctx := context.Background()

	enableKVv2(t, vc, "kv")

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"somekey": {Engine: "nonexistent-engine"},
		},
		KVMount:    "kv",
		UserPrefix: testPrefix(t),
	}, vc, testIO(&buf))

	enrolled, err := mgr.CheckAll(ctx)
	if err != nil {
		t.Fatalf("CheckAll() error: %v", err)
	}
	if enrolled {
		t.Error("enrolled=true, want false — unknown engine should be skipped")
	}
}

func TestCheckAll_Empty(t *testing.T) {
	vc := skipIfNoVault(t)
	ctx := context.Background()

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: nil,
		KVMount:    "kv",
		UserPrefix: testPrefix(t),
	}, vc, testIO(&buf))

	enrolled, err := mgr.CheckAll(ctx)
	if err != nil {
		t.Fatalf("CheckAll() error: %v", err)
	}
	if enrolled {
		t.Error("enrolled=true, want false — no enrolments configured")
	}
}

func TestStatuses(t *testing.T) {
	vc := skipIfNoVault(t)
	ctx := context.Background()

	engEnrolled := &mockEngine{name: "Enrolled", fields: []string{"token"}}
	engPending := &mockEngine{name: "Pending", fields: []string{"token"}}
	RegisterEngine("test-statuses-enrolled", engEnrolled)
	RegisterEngine("test-statuses-pending", engPending)
	t.Cleanup(func() {
		UnregisterEngine("test-statuses-enrolled")
		UnregisterEngine("test-statuses-pending")
	})

	enableKVv2(t, vc, "kv")
	prefix := testPrefix(t)
	seedKVv2(t, vc, "kv", prefix+"done", map[string]any{"token": "abc"})

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"done":    {Engine: "test-statuses-enrolled"},
			"todo":    {Engine: "test-statuses-pending"},
			"unknown": {Engine: "nonexistent-engine"},
		},
		KVMount:    "kv",
		UserPrefix: prefix,
	}, vc, testIO(&buf))

	statuses := mgr.Statuses(ctx)
	if len(statuses) != 3 {
		t.Fatalf("len(statuses) = %d, want 3", len(statuses))
	}

	// Statuses are sorted by key: done, todo, unknown
	want := []struct {
		key      string
		engine   string
		enrolled bool
		hasErr   bool
	}{
		{"done", "test-statuses-enrolled", true, false},
		{"todo", "test-statuses-pending", false, false},
		{"unknown", "nonexistent-engine", false, true},
	}
	for i, w := range want {
		got := statuses[i]
		if got.Key != w.key {
			t.Errorf("statuses[%d].Key = %q, want %q", i, got.Key, w.key)
		}
		if got.Engine != w.engine {
			t.Errorf("statuses[%d].Engine = %q, want %q", i, got.Engine, w.engine)
		}
		if got.Enrolled != w.enrolled {
			t.Errorf("statuses[%d].Enrolled = %v, want %v", i, got.Enrolled, w.enrolled)
		}
		if (got.Error != "") != w.hasErr {
			t.Errorf("statuses[%d].Error = %q, wanted error=%v", i, got.Error, w.hasErr)
		}
	}
	if statuses[0].EngineName != "Enrolled" {
		t.Errorf("statuses[0].EngineName = %q, want %q", statuses[0].EngineName, "Enrolled")
	}
}

func TestRunOne_Unknown(t *testing.T) {
	vc := skipIfNoVault(t)
	ctx := context.Background()

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"gh": {Engine: "github"},
		},
		KVMount:    "kv",
		UserPrefix: testPrefix(t),
	}, vc, testIO(&buf))

	err := mgr.RunOne(ctx, "does-not-exist")
	if !errors.Is(err, ErrUnknownEnrolment) {
		t.Fatalf("RunOne unknown: err = %v, want wraps ErrUnknownEnrolment", err)
	}
}

func TestRunOne_Success(t *testing.T) {
	vc := skipIfNoVault(t)
	ctx := context.Background()

	eng := &mockEngine{name: "RunOne", fields: []string{"token"}, creds: map[string]string{"token": "v1"}}
	RegisterEngine("test-runone", eng)
	t.Cleanup(func() { UnregisterEngine("test-runone") })

	enableKVv2(t, vc, "kv")
	prefix := testPrefix(t)

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"item": {Engine: "test-runone"},
		},
		KVMount:    "kv",
		UserPrefix: prefix,
	}, vc, testIO(&buf))

	if err := mgr.RunOne(ctx, "item"); err != nil {
		t.Fatalf("RunOne: %v", err)
	}
	if eng.called != 1 {
		t.Errorf("engine called %d times, want 1", eng.called)
	}
	secret, err := vc.ReadKVv2(ctx, "kv", prefix+"item")
	if err != nil {
		t.Fatalf("ReadKVv2: %v", err)
	}
	if secret == nil || secret.Data["token"] != "v1" {
		t.Errorf("vault token = %v, want %q", secret, "v1")
	}
}

func TestRunOne_Rerun(t *testing.T) {
	// RunOne deliberately re-runs an enrolment even if its target is
	// already populated — CheckAll is the "fill gaps" path; RunOne is
	// the explicit re-enrol entry point.
	vc := skipIfNoVault(t)
	ctx := context.Background()

	eng := &mockEngine{name: "Rerun", fields: []string{"token"}, creds: map[string]string{"token": "fresh"}}
	RegisterEngine("test-rerun", eng)
	t.Cleanup(func() { UnregisterEngine("test-rerun") })

	enableKVv2(t, vc, "kv")
	prefix := testPrefix(t)
	seedKVv2(t, vc, "kv", prefix+"item", map[string]any{"token": "stale"})

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"item": {Engine: "test-rerun"},
		},
		KVMount:    "kv",
		UserPrefix: prefix,
	}, vc, testIO(&buf))

	if err := mgr.RunOne(ctx, "item"); err != nil {
		t.Fatalf("RunOne: %v", err)
	}
	if eng.called != 1 {
		t.Errorf("engine should run despite existing creds, called %d times", eng.called)
	}
	secret, _ := vc.ReadKVv2(ctx, "kv", prefix+"item")
	if secret.Data["token"] != "fresh" {
		t.Errorf("token = %v, want %q", secret.Data["token"], "fresh")
	}
}

func TestRunOne_EngineFailure(t *testing.T) {
	vc := skipIfNoVault(t)
	ctx := context.Background()

	eng := &mockEngine{name: "Fail", fields: []string{"token"}, err: fmt.Errorf("boom")}
	RegisterEngine("test-runone-fail", eng)
	t.Cleanup(func() { UnregisterEngine("test-runone-fail") })

	enableKVv2(t, vc, "kv")
	prefix := testPrefix(t)

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"item": {Engine: "test-runone-fail"},
		},
		KVMount:    "kv",
		UserPrefix: prefix,
	}, vc, testIO(&buf))

	err := mgr.RunOne(ctx, "item")
	if err == nil {
		t.Fatal("RunOne should fail when engine errors")
	}
	// Engine error message should propagate so the CLI can show it.
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error = %v, want it to contain %q", err, "boom")
	}
}

func TestRunOne_IncompleteCredentials(t *testing.T) {
	vc := skipIfNoVault(t)
	ctx := context.Background()

	// Engine returns success but omits the required "token" field.
	eng := &mockEngine{name: "Partial", fields: []string{"token"}, creds: map[string]string{}}
	RegisterEngine("test-runone-partial", eng)
	t.Cleanup(func() { UnregisterEngine("test-runone-partial") })

	enableKVv2(t, vc, "kv")
	prefix := testPrefix(t)

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"item": {Engine: "test-runone-partial"},
		},
		KVMount:    "kv",
		UserPrefix: prefix,
	}, vc, testIO(&buf))

	err := mgr.RunOne(ctx, "item")
	if err == nil {
		t.Fatal("RunOne should fail when engine returns incomplete credentials")
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("error = %v, want it to mention incomplete credentials", err)
	}
}

func TestUpdateConfig(t *testing.T) {
	vc := skipIfNoVault(t)

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: nil,
		KVMount:    "kv",
		UserPrefix: testPrefix(t),
	}, vc, testIO(&buf))

	newMap := map[string]config.Enrolment{
		"gh": {Engine: "github"},
	}
	mgr.UpdateConfig(newMap)

	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if len(mgr.cfg.Enrolments) != 1 {
		t.Errorf("after UpdateConfig, len(Enrolments) = %d, want 1", len(mgr.cfg.Enrolments))
	}
}
