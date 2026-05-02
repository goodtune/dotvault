package regfile

import (
	"bytes"
	"fmt"

	"github.com/goodtune/dotvault/internal/config"
	"gopkg.in/yaml.v3"
)

// MarshalYAML renders cfg as the canonical YAML form accepted by config.Load.
// Output uses 2-space indentation, matching the project's existing
// config.dev.yaml style, and includes a trailing newline.
//
// In current yaml.v3 versions map keys are emitted in sorted order, which
// keeps Enrolments and per-engine Settings stable across runs. That
// behaviour is not formally guaranteed by the YAML spec, so the test
// suite includes a regression test that pins it; if a future yaml.v3
// release drops the implicit sort the test will fail loudly and prompt
// us to switch to an explicit yaml.Node walk.
//
// Empty optional fields are emitted explicitly (e.g. `auth_method: ""`)
// rather than omitted, because the source of this call is typically a
// .reg file or registry-loaded config where the empty-string distinction
// matters: re-importing a YAML config that omits a field would leave any
// previously-set value in place, whereas an explicit empty string clears
// it. This matches the clearing semantics already used by reg-import.
func MarshalYAML(cfg *config.Config) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cannot marshal nil config")
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return nil, fmt.Errorf("encode yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("close yaml encoder: %w", err)
	}
	return buf.Bytes(), nil
}
