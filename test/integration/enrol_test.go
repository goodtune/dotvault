package integration

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/enrol"
)

// testEnrolIO returns an IO that suppresses terminal output.
func testEnrolIO(t *testing.T) enrol.IO {
	t.Helper()
	var buf bytes.Buffer
	return enrol.IO{
		Out:     &buf,
		Browser: func(url string) error { return nil },
		Log:     slog.New(slog.NewTextHandler(&buf, nil)),
	}
}

// mockGitHubEngine returns canned credentials without running a real OAuth flow.
type mockGitHubEngine struct {
	token string
	user  string
}

func (e *mockGitHubEngine) Name() string {
	return "GitHub"
}

func (e *mockGitHubEngine) Fields() []string {
	return []string{"oauth_token"}
}
func (e *mockGitHubEngine) Run(_ context.Context, _ map[string]any, _ enrol.IO) (map[string]string, error) {
	return map[string]string{
		"oauth_token": e.token,
		"user":        e.user,
	}, nil
}

func TestEnrolmentFullFlow(t *testing.T) {
	vc := testVC
	ctx := context.Background()

	// Ensure the KV mount exists
	if err := vc.EnableKVv2(ctx, "secret"); err != nil && !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("EnableKVv2: %v", err)
	}

	// Register a mock engine that returns known credentials without running real OAuth
	mockEng := &mockGitHubEngine{
		token: "gho_test_token",
		user:  "testuser",
	}
	enrol.RegisterEngine("mock-gh", mockEng)
	defer enrol.UnregisterEngine("mock-gh")

	// Use a per-test prefix so tests are idempotent against a long-lived Vault.
	prefix := fmt.Sprintf("users/enroltest-%d/", time.Now().UnixNano())

	io := testEnrolIO(t)
	mgr := enrol.NewManager(enrol.ManagerConfig{
		Enrolments: map[string]config.Enrolment{
			"gh": {Engine: "mock-gh"},
		},
		KVMount:    "secret",
		UserPrefix: prefix,
	}, vc, io)

	enrolled, err := mgr.CheckAll(ctx)
	if err != nil {
		t.Fatalf("CheckAll() error: %v", err)
	}
	if !enrolled {
		t.Error("enrolled=false, want true — secrets should have been written")
	}

	// Verify the secret was written to Vault
	secret, err := vc.ReadKVv2(ctx, "secret", prefix+"gh")
	if err != nil {
		t.Fatalf("ReadKVv2 error: %v", err)
	}
	if secret == nil {
		t.Fatal("expected secret in vault after enrolment, got nil")
	}
	if secret.Data["oauth_token"] != "gho_test_token" {
		t.Errorf("oauth_token = %v, want %q", secret.Data["oauth_token"], "gho_test_token")
	}
	if secret.Data["user"] != "testuser" {
		t.Errorf("user = %v, want %q", secret.Data["user"], "testuser")
	}

	// Second CheckAll should be a no-op (credentials already present)
	enrolled2, err := mgr.CheckAll(ctx)
	if err != nil {
		t.Fatalf("second CheckAll() error: %v", err)
	}
	if enrolled2 {
		t.Error("second CheckAll: enrolled=true, want false — credentials already complete")
	}
}

// TestEnrolmentDefaultClientIDAndScopes was dropped: it posted directly to the
// mock OAuth server without exercising GitHubEngine, so it gave false confidence.
// A proper replacement would run GitHubEngine against a TLS mock server and verify
// the actual HTTP requests it sends — deferred to a future PR.
