package config

import (
	"strings"
	"testing"
	"time"
)

func TestSlackWorkspaces(t *testing.T) {
	good, err := SlackWorkspaces(map[string]any{"workspaces": []any{"acme", "acme-eng", "a1"}})
	if err != nil || strings.Join(good, ",") != "acme,acme-eng,a1" {
		t.Fatalf("got %v, %v", good, err)
	}
	for name, settings := range map[string]map[string]any{
		"missing":   {},
		"not list":  {"workspaces": "acme"},
		"empty":     {"workspaces": []any{}},
		"non-str":   {"workspaces": []any{1}},
		"upper":     {"workspaces": []any{"Acme"}},
		"dotted":    {"workspaces": []any{"acme.slack.com"}},
		"leading -": {"workspaces": []any{"-acme"}},
		"reserved":  {"workspaces": []any{"expires_at"}},
		"duplicate": {"workspaces": []any{"acme", "acme"}},
	} {
		if _, err := SlackWorkspaces(settings); err == nil || !strings.HasPrefix(err.Error(), "workspaces") {
			t.Errorf("%s: err = %v, want one naming the setting", name, err)
		}
	}
}

func TestSlackRefreshInterval(t *testing.T) {
	if d, err := SlackRefreshInterval(map[string]any{}); err != nil || d != DefaultSlackRefreshInterval {
		t.Errorf("default = %v, %v", d, err)
	}
	if d, err := SlackRefreshInterval(map[string]any{"refresh_interval": "2d"}); err != nil || d != 48*time.Hour {
		t.Errorf("2d = %v, %v", d, err)
	}
	for _, v := range []any{"30m", "soon", 5} {
		if _, err := SlackRefreshInterval(map[string]any{"refresh_interval": v}); err == nil {
			t.Errorf("%v: want an error", v)
		}
	}
}

func TestValidateEnrolmentChecksSlackSettings(t *testing.T) {
	err := validateEnrolment("slack/slk", Enrolment{Engine: "slack", Settings: map[string]any{}})
	if err == nil || !strings.Contains(err.Error(), `enrolments["slack/slk"].settings.workspaces`) {
		t.Fatalf("err = %v", err)
	}
	if err := validateEnrolment("slack/slk", Enrolment{Engine: "slack", Settings: map[string]any{"workspaces": []any{"acme"}}}); err != nil {
		t.Fatal(err)
	}
}
