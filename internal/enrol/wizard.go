package enrol

import (
	"context"
	"fmt"

	"github.com/goodtune/dotvault/internal/config"
)

// pendingEnrolment is an enrolment that needs to run.
type pendingEnrolment struct {
	key       string
	enrolment config.Enrolment
	engine    Engine
}

// runWizard runs pending enrolments sequentially and returns the credentials
// for each successful one. Failures are logged and skipped.
func runWizard(ctx context.Context, pending []pendingEnrolment, io IO) map[string]map[string]string {
	total := len(pending)
	results := make(map[string]map[string]string)

	fmt.Fprintf(io.Out, "dotvault: checking enrolments...\n")
	for _, p := range pending {
		fmt.Fprintf(io.Out, "  ○ %s (%s) — missing\n", p.key, p.engine.Name())
	}
	fmt.Fprintln(io.Out)

	for i, p := range pending {
		if ctx.Err() != nil {
			return results
		}

		fmt.Fprintf(io.Out, "Enrolment [%d/%d]: %s\n", i+1, total, p.engine.Name())

		creds, err := p.engine.Run(ctx, p.enrolment.Settings, io)
		if err != nil {
			if ctx.Err() != nil {
				return results
			}
			io.Log.Error("enrolment failed", "key", p.key, "engine", p.enrolment.Engine, "error", err)
			fmt.Fprintf(io.Out, "✗ %s (%s) — failed: %v\n\n", p.key, p.engine.Name(), err)
			continue
		}

		results[p.key] = creds

		user := creds["user"]
		if user != "" {
			fmt.Fprintf(io.Out, "✓ %s (%s) — credentials acquired for @%s\n\n", p.key, p.engine.Name(), user)
		} else {
			fmt.Fprintf(io.Out, "✓ %s (%s) — credentials acquired\n\n", p.key, p.engine.Name())
		}
	}

	return results
}

// copyToClipboard attempts to copy the given text to the system clipboard.
// Best-effort: if no clipboard tool is found, it silently continues.
func copyToClipboard(text string) {
	// Implemented per-platform in clipboard_*.go
	tryClipboard(text)
}
