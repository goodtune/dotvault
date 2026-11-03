package config

import (
	"strings"
	"testing"
)

func TestSlackWorkspaces(t *testing.T) {
	good, err := SlackWorkspaces(map[string]any{"workspaces": []any{"acme", "acme-eng", "a1", "company.enterprise", "enterprise", strings.Repeat("a", 63) + ".enterprise"}})
	if err != nil || len(good) != 6 || good[3] != "company.enterprise" {
		t.Fatalf("got %v, %v", good, err)
	}
	for name, settings := range map[string]map[string]any{
		"missing":   {},
		"not list":  {"workspaces": "acme"},
		"empty":     {"workspaces": []any{}},
		"non-str":   {"workspaces": []any{1}},
		"upper":     {"workspaces": []any{"Acme"}},
		"dotted":    {"workspaces": []any{"acme.slack.com"}},
		"grid host": {"workspaces": []any{"acme.enterprise.slack.com"}},
		"bare grid": {"workspaces": []any{".enterprise"}},
		"two dots":  {"workspaces": []any{"a.b.enterprise"}},
		"twice":     {"workspaces": []any{"x.enterprise.enterprise"}},
		"trailing":  {"workspaces": []any{"acme.enterprise."}},
		"hyphen":    {"workspaces": []any{"acme-.enterprise"}},
		"too long":  {"workspaces": []any{strings.Repeat("a", 64) + ".enterprise"}},
		"leading -": {"workspaces": []any{"-acme"}},
		"duplicate": {"workspaces": []any{"acme", "acme"}},
	} {
		if _, err := SlackWorkspaces(settings); err == nil || !strings.HasPrefix(err.Error(), "workspaces") {
			t.Errorf("%s: err = %v, want one naming the setting", name, err)
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
