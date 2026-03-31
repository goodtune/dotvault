package enrol

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
)

func testWizardIO(buf *bytes.Buffer) IO {
	return IO{
		Out:     buf,
		Browser: func(url string) error { return nil },
		Log:     slog.New(slog.NewTextHandler(buf, nil)),
	}
}

func TestWizard_ProgressDisplay(t *testing.T) {
	eng1 := &mockEngine{name: "ServiceA", fields: []string{"tok"}, creds: map[string]string{"tok": "a"}}
	eng2 := &mockEngine{name: "ServiceB", fields: []string{"tok"}, creds: map[string]string{"tok": "b"}}

	pending := []pendingEnrolment{
		{key: "svc-a", enrolment: config.Enrolment{Engine: "svc-a"}, engine: eng1},
		{key: "svc-b", enrolment: config.Enrolment{Engine: "svc-b"}, engine: eng2},
	}

	var buf bytes.Buffer
	results := runWizard(context.Background(), pending, testWizardIO(&buf))

	out := buf.String()
	if !strings.Contains(out, "[1/2]") {
		t.Errorf("expected progress [1/2] in output, got:\n%s", out)
	}
	if !strings.Contains(out, "[2/2]") {
		t.Errorf("expected progress [2/2] in output, got:\n%s", out)
	}
	if len(results) != 2 {
		t.Errorf("results len = %d, want 2", len(results))
	}
}

func TestWizard_ContinuesAfterFailure(t *testing.T) {
	engFail := &mockEngine{name: "Fail", fields: []string{"x"}, err: errors.New("denied")}
	engOK := &mockEngine{name: "OK", fields: []string{"x"}, creds: map[string]string{"x": "v"}}

	pending := []pendingEnrolment{
		{key: "k1", enrolment: config.Enrolment{Engine: "fail"}, engine: engFail},
		{key: "k2", enrolment: config.Enrolment{Engine: "ok"}, engine: engOK},
	}

	var buf bytes.Buffer
	results := runWizard(context.Background(), pending, testWizardIO(&buf))

	if _, ok := results["k1"]; ok {
		t.Error("k1 should not be in results after failure")
	}
	if _, ok := results["k2"]; !ok {
		t.Error("k2 should be in results after k1 failure")
	}
}

func TestWizard_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	eng := &mockEngine{name: "Test", fields: []string{"x"}, creds: map[string]string{"x": "v"}}
	pending := []pendingEnrolment{
		{key: "k1", enrolment: config.Enrolment{Engine: "test"}, engine: eng},
	}

	var buf bytes.Buffer
	results := runWizard(ctx, pending, testWizardIO(&buf))

	// Context was already cancelled — wizard should return immediately with no results
	if len(results) != 0 {
		t.Errorf("expected no results after context cancellation, got %d", len(results))
	}
	if eng.called != 0 {
		t.Errorf("engine should not be called after context cancellation, called %d times", eng.called)
	}
}
