package enrol

import (
	"bytes"
	"context"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

func TestCheckAll_WebMode_SkipsWizard(t *testing.T) {
	vc := skipIfNoVault(t)
	ctx := context.Background()

	eng := &mockEngine{name: "test", fields: []string{"token"}, creds: map[string]string{"token": "abc"}}
	RegisterEngine("test-webmode", eng)
	t.Cleanup(func() { UnregisterEngine("test-webmode") })

	enableKVv2(t, vc, "kv")
	prefix := testPrefix(t)

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"webkey": {Engine: "test-webmode"},
		},
		KVMount:    "kv",
		UserPrefix: prefix,
		WebMode:    true,
	}, vc, testIO(&buf))

	enrolled, err := mgr.CheckAll(ctx)
	if err != nil {
		t.Fatalf("CheckAll() error: %v", err)
	}
	if enrolled {
		t.Error("enrolled=true, want false — web mode should skip wizard")
	}
	if eng.called != 0 {
		t.Errorf("engine called %d times, want 0 — web mode should not run engine", eng.called)
	}
}

func TestFindPending_ReturnsPendingInfo(t *testing.T) {
	vc := skipIfNoVault(t)
	ctx := context.Background()

	eng := &mockEngine{name: "TestEngine", fields: []string{"token"}}
	RegisterEngine("test-findpending", eng)
	t.Cleanup(func() { UnregisterEngine("test-findpending") })

	enableKVv2(t, vc, "kv")
	prefix := testPrefix(t)

	var buf bytes.Buffer
	mgr := NewManager(ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"mykey": {Engine: "test-findpending"},
		},
		KVMount:    "kv",
		UserPrefix: prefix,
	}, vc, testIO(&buf))

	pending, err := mgr.FindPending(ctx)
	if err != nil {
		t.Fatalf("FindPending() error: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("FindPending() returned %d items, want 1", len(pending))
	}
	if pending[0].Key != "mykey" {
		t.Errorf("Key = %q, want %q", pending[0].Key, "mykey")
	}
	if pending[0].EngineName != "TestEngine" {
		t.Errorf("EngineName = %q, want %q", pending[0].EngineName, "TestEngine")
	}
}
