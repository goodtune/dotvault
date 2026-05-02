package enrol

import (
	"context"
	"reflect"
	"testing"
)

func TestCopyEngine_Fields_Static(t *testing.T) {
	e := &CopyEngine{}
	if got := e.Fields(); got != nil {
		t.Errorf("Fields() = %v, want nil", got)
	}
}

func TestCopyEngine_FieldsFromSettings(t *testing.T) {
	e := &CopyEngine{}

	tests := []struct {
		name     string
		settings map[string]any
		want     []string
	}{
		{
			name: "single key",
			settings: map[string]any{
				"template": `{"token": "{{ .data.key }}"}`,
			},
			want: []string{"token"},
		},
		{
			name: "multiple keys sorted",
			settings: map[string]any{
				"template": `{"zebra": "z", "apple": "a", "mango": "m"}`,
			},
			want: []string{"apple", "mango", "zebra"},
		},
		{
			name: "unquoted dynamic value",
			settings: map[string]any{
				// Action lands outside JSON string quotes; field
				// inference must still work without rendering the
				// template against real data.
				"template": `{"port": {{ .data.port }}, "host": "{{ .data.host }}"}`,
			},
			want: []string{"host", "port"},
		},
		{
			name:     "missing template",
			settings: map[string]any{},
			want:     nil,
		},
		{
			name: "unparseable template",
			settings: map[string]any{
				"template": "{ this is not json",
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.FieldsFromSettings(tt.settings)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FieldsFromSettings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStripTemplateActions(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no action", `{"a":"b"}`, `{"a":"b"}`},
		{"quoted action", `{"a":"{{.x}}"}`, `{"a":"null"}`},
		{"unquoted action", `{"a":{{.x}}}`, `{"a":null}`},
		{"multi-action", `{"a":"{{.x}}","b":{{.y}}}`, `{"a":"null","b":null}`},
		{"unmatched open", `{"a":{{`, `{"a":{{`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripTemplateActions(tt.in); got != tt.want {
				t.Errorf("stripTemplateActions(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCopyEngine_WatchSources(t *testing.T) {
	e := &CopyEngine{}

	t.Run("substitutes username", func(t *testing.T) {
		got := e.WatchSources(map[string]any{
			"from": map[string]any{
				"mount": "kv",
				"path":  "apps/someapp/keys/{{.user}}",
			},
		}, "alice")
		want := []WatchSource{{Mount: "kv", Path: "apps/someapp/keys/alice"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("WatchSources() = %v, want %v", got, want)
		}
	})

	t.Run("invalid settings returns nil", func(t *testing.T) {
		if got := e.WatchSources(map[string]any{}, "alice"); got != nil {
			t.Errorf("WatchSources(empty) = %v, want nil", got)
		}
	})
}

func TestCopyEngine_Run_RequiresVault(t *testing.T) {
	e := &CopyEngine{}
	_, err := e.Run(context.Background(), map[string]any{}, IO{})
	if err == nil {
		t.Fatal("expected error when Vault is nil")
	}
}

func TestCopyEngine_Run_RequiresUsername(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)
	e := &CopyEngine{}
	_, err := e.Run(context.Background(), map[string]any{
		"from": map[string]any{
			"mount": "kv",
			"path":  "apps/x/keys/{{.user}}",
		},
		"format":   "json",
		"template": `{"token": "x"}`,
	}, IO{Vault: vc})
	if err == nil {
		t.Fatal("expected error when Username is empty")
	}
}

func TestCopyEngine_Run_RequiresKVMountWhenTargetPathSet(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)
	e := &CopyEngine{}
	_, err := e.Run(context.Background(), map[string]any{
		"from": map[string]any{
			"mount": "kv",
			"path":  "apps/x/keys/{{.user}}",
		},
		"format":   "json",
		"template": `{"token": "x"}`,
	}, IO{
		Vault:      vc,
		Username:   "alice",
		TargetPath: "users/alice/x",
		// KVMount intentionally empty.
	})
	if err == nil {
		t.Fatal("expected error when TargetPath is set but KVMount is empty")
	}
}

func TestCopyEngine_Run_HappyPath(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)
	fv.seed("apps/someapp/keys/alice", map[string]string{"key": "secret-value"})

	e := &CopyEngine{}
	got, err := e.Run(context.Background(), map[string]any{
		"from": map[string]any{
			"mount": "kv",
			"path":  "apps/someapp/keys/{{.user}}",
		},
		"format":   "json",
		"template": `{"token": "{{ .data.key }}"}`,
	}, IO{
		Vault:      vc,
		KVMount:    "kv",
		Username:   "alice",
		TargetPath: "users/alice/someapp",
	})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if got["token"] != "secret-value" {
		t.Errorf("token = %q, want %q", got["token"], "secret-value")
	}
}

func TestCopyEngine_Run_PreservesUnrelatedTargetKeys(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)
	fv.seed("apps/someapp/keys/alice", map[string]string{"key": "new-value"})
	fv.seed("users/alice/someapp", map[string]string{
		"username": "alice",
		"token":    "old-value",
	})

	e := &CopyEngine{}
	got, err := e.Run(context.Background(), map[string]any{
		"from": map[string]any{
			"mount": "kv",
			"path":  "apps/someapp/keys/{{.user}}",
		},
		"format":   "json",
		"template": `{"token": "{{ .data.key }}"}`,
	}, IO{
		Vault:      vc,
		KVMount:    "kv",
		Username:   "alice",
		TargetPath: "users/alice/someapp",
	})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if got["token"] != "new-value" {
		t.Errorf("token = %q, want %q (template should overwrite existing token)", got["token"], "new-value")
	}
	if got["username"] != "alice" {
		t.Errorf("username = %q, want %q (existing key not produced by template should be preserved)", got["username"], "alice")
	}
}

func TestCopyEngine_Run_SourceMissing(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	e := &CopyEngine{}
	_, err := e.Run(context.Background(), map[string]any{
		"from": map[string]any{
			"mount": "kv",
			"path":  "apps/someapp/keys/{{.user}}",
		},
		"format":   "json",
		"template": `{"token": "{{ .data.key }}"}`,
	}, IO{
		Vault:      vc,
		KVMount:    "kv",
		Username:   "alice",
		TargetPath: "users/alice/someapp",
	})
	if err == nil {
		t.Fatal("expected error when source secret is missing")
	}
}

func TestCopyEngine_Run_UnsupportedFormat(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)

	e := &CopyEngine{}
	_, err := e.Run(context.Background(), map[string]any{
		"from": map[string]any{
			"mount": "kv",
			"path":  "apps/someapp/keys/{{.user}}",
		},
		"format":   "yaml",
		"template": `token: x`,
	}, IO{
		Vault:    vc,
		KVMount:  "kv",
		Username: "alice",
	})
	if err == nil {
		t.Fatal("expected error for non-json format")
	}
}

func TestCopyEngine_Run_TemplateRequired(t *testing.T) {
	fv := newFakeVault("kv")
	vc := fv.serve(t)
	fv.seed("apps/someapp/keys/alice", map[string]string{"key": "v"})

	e := &CopyEngine{}
	_, err := e.Run(context.Background(), map[string]any{
		"from": map[string]any{
			"mount": "kv",
			"path":  "apps/someapp/keys/{{.user}}",
		},
		"format": "json",
	}, IO{
		Vault:    vc,
		KVMount:  "kv",
		Username: "alice",
	})
	if err == nil {
		t.Fatal("expected error when template is missing")
	}
}
