package enrol

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
)

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
		Out:     buf,
		Browser: func(url string) error { return nil },
		Log:     slog.New(slog.NewTextHandler(buf, nil)),
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
	seedKVv2(t, vc, "kv", "users/testuser/mykey", map[string]any{"token": "existing"})

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"mykey": {Engine: "test-present"},
		},
		KVMount:    "kv",
		UserPrefix: "users/testuser/",
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

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"newkey": {Engine: "test-missing"},
		},
		KVMount:    "kv",
		UserPrefix: "users/testuser2/",
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
	secret, err := vc.ReadKVv2(ctx, "kv", "users/testuser2/newkey")
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

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"keyok":   {Engine: "test-ok"},
			"keyfail": {Engine: "test-fail"},
		},
		KVMount:    "kv",
		UserPrefix: "users/testuser3/",
	}, vc, testIO(&buf))

	enrolled, err := mgr.CheckAll(ctx)
	if err != nil {
		t.Fatalf("CheckAll() error: %v", err)
	}
	if !enrolled {
		t.Error("enrolled=false, want true — at least one should succeed")
	}

	// ok key should be in vault
	secret, err := vc.ReadKVv2(ctx, "kv", "users/testuser3/keyok")
	if err != nil {
		t.Fatalf("ReadKVv2() error for keyok: %v", err)
	}
	if secret == nil {
		t.Error("expected keyok in vault")
	}
	// fail key should not be in vault
	secret, err = vc.ReadKVv2(ctx, "kv", "users/testuser3/keyfail")
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
		UserPrefix: "users/testuser4/",
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
		UserPrefix: "users/x/",
	}, vc, testIO(&buf))

	enrolled, err := mgr.CheckAll(ctx)
	if err != nil {
		t.Fatalf("CheckAll() error: %v", err)
	}
	if enrolled {
		t.Error("enrolled=true, want false — no enrolments configured")
	}
}

func TestUpdateConfig(t *testing.T) {
	vc := skipIfNoVault(t)

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: nil,
		KVMount:    "kv",
		UserPrefix: "users/x/",
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
