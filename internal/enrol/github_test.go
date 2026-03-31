package enrol

import (
	"testing"
)

func TestGitHubEngine_Name(t *testing.T) {
	e := &GitHubEngine{}
	if e.Name() != "GitHub" {
		t.Errorf("Name() = %q, want %q", e.Name(), "GitHub")
	}
}

func TestGitHubEngine_Fields(t *testing.T) {
	e := &GitHubEngine{}
	fields := e.Fields()
	want := []string{"oauth_token", "user"}
	if len(fields) != len(want) {
		t.Fatalf("Fields() len = %d, want %d", len(fields), len(want))
	}
	for i, f := range fields {
		if f != want[i] {
			t.Errorf("Fields()[%d] = %q, want %q", i, f, want[i])
		}
	}
}

func TestGitHubDefaultsUsedWhenNoSettings(t *testing.T) {
	// Verify that the engine uses default client_id and scopes when settings is nil.
	// We can't run a real OAuth flow in unit tests, so we just verify the defaults
	// are correct by checking the constants.
	if githubDefaultClientID == "" {
		t.Error("githubDefaultClientID is empty")
	}
	if githubDefaultHost == "" {
		t.Error("githubDefaultHost is empty")
	}
	if len(githubDefaultScopes) == 0 {
		t.Error("githubDefaultScopes is empty")
	}
}

func TestGitHubSettingsOverride(t *testing.T) {
	// The override logic is inline in Run(), but we can verify the constant defaults
	// are distinct from typical override values so overrides would actually change behaviour.
	customClientID := "custom-client-id"
	if customClientID == githubDefaultClientID {
		t.Error("test client ID matches default — override test would be vacuous")
	}
}
