package tmpl

import (
	"encoding/base64"
	"testing"
)

func TestRender(t *testing.T) {
	tests := []struct {
		name     string
		template string
		data     map[string]any
		want     string
		wantErr  bool
	}{
		{
			name:     "simple substitution",
			template: `token: "{{.token}}"`,
			data:     map[string]any{"token": "abc123"},
			want:     `token: "abc123"`,
		},
		{
			name: "multiple fields",
			template: `github.com:
  oauth_token: "{{.token}}"
  user: "{{.user}}"
  git_protocol: https`,
			data: map[string]any{"token": "ghp_xxx", "user": "gary"},
			want: `github.com:
  oauth_token: "ghp_xxx"
  user: "gary"
  git_protocol: https`,
		},
		{
			name:     "default function with value present",
			template: `port: {{default "8080" .port}}`,
			data:     map[string]any{"port": "9090"},
			want:     `port: 9090`,
		},
		{
			name:     "default function with missing value",
			template: `port: {{default "8080" .port}}`,
			data:     map[string]any{},
			want:     `port: 8080`,
		},
		{
			name:     "default function with pipe syntax",
			template: `port: {{.port | default "8080"}}`,
			data:     map[string]any{"port": "9090"},
			want:     `port: 9090`,
		},
		{
			name:     "default function with pipe and missing value",
			template: `port: {{.port | default "8080"}}`,
			data:     map[string]any{},
			want:     `port: 8080`,
		},
		{
			name:     "base64encode",
			template: `auth: {{base64encode .creds}}`,
			data:     map[string]any{"creds": "user:pass"},
			want:     `auth: ` + base64.StdEncoding.EncodeToString([]byte("user:pass")),
		},
		{
			name:     "base64decode",
			template: `plain: {{base64decode .encoded}}`,
			data:     map[string]any{"encoded": base64.StdEncoding.EncodeToString([]byte("hello"))},
			want:     `plain: hello`,
		},
		{
			name:     "quote function",
			template: `val: {{quote .val}}`,
			data:     map[string]any{"val": `it's a "test"`},
			want:     `val: 'it'"'"'s a "test"'`,
		},
		{
			name:     "invalid template syntax",
			template: `{{.foo`,
			data:     map[string]any{},
			wantErr:  true,
		},
		{
			name:     "missing required field errors",
			template: `{{.token}}`,
			data:     map[string]any{},
			want:     `<no value>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Render(tt.name, tt.template, tt.data)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Render() =\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestRenderUsernameFunction(t *testing.T) {
	// RenderWithUsername binds {{ username }} to the supplied identity, so a
	// rule template can build paths from the OS account without the username
	// being a field in the secret.
	got, err := RenderWithUsername("ssh", `RemoteForward /home/{{ username }}/.ssh/agent.sock`, map[string]any{}, "gary")
	if err != nil {
		t.Fatalf("RenderWithUsername: %v", err)
	}
	if want := `RemoteForward /home/gary/.ssh/agent.sock`; got != want {
		t.Errorf("RenderWithUsername() = %q, want %q", got, want)
	}

	// A secret field named "user" is independent of {{ username }} — they do
	// not collide, because the username is a function, not a data key.
	got, err = RenderWithUsername("both", `{{ .user }}/{{ username }}`, map[string]any{"user": "secretval"}, "osuser")
	if err != nil {
		t.Fatalf("RenderWithUsername (both): %v", err)
	}
	if want := "secretval/osuser"; got != want {
		t.Errorf("RenderWithUsername (both) = %q, want %q", got, want)
	}

	// Plain Render leaves {{ username }} bound to the empty string rather than
	// failing to parse, so the function is uniformly available.
	got, err = Render("plain", `[{{ username }}]`, map[string]any{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if want := "[]"; got != want {
		t.Errorf("Render() with username func = %q, want %q", got, want)
	}
}

// TestRenderWithUsername_EmptyContext pins the keyless-rule contract: a rule
// with no vault_key renders against an empty data context, where {{ username }}
// (a function) still resolves but a reference to a would-be secret field
// degrades to Go's <no value> sentinel rather than erroring. This is what lets
// a keyless ssh_config template build per-user paths with no Vault data.
func TestRenderWithUsername_EmptyContext(t *testing.T) {
	got, err := RenderWithUsername("keyless", `User {{ username }} field={{ .secret_field }}`, map[string]any{}, "goodtune")
	if err != nil {
		t.Fatalf("RenderWithUsername (empty context): %v", err)
	}
	if want := "User goodtune field=<no value>"; got != want {
		t.Errorf("empty-context render = %q, want %q", got, want)
	}
}

func TestRenderEnvFunction(t *testing.T) {
	t.Setenv("DOTVAULT_TEST_VAR", "test-value")

	got, err := Render("env-test", `home: {{env "DOTVAULT_TEST_VAR"}}`, map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `home: test-value`
	if got != want {
		t.Errorf("Render() = %q, want %q", got, want)
	}
}
