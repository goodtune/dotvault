package regfile

import (
	"bytes"
	"fmt"

	"github.com/goodtune/dotvault/internal/config"
	"gopkg.in/yaml.v3"
)

// MarshalYAML renders cfg as the canonical YAML form accepted by config.Load.
// The output is sorted (yaml.v3 sorts map keys alphabetically) and uses
// 2-space indentation, matching the project's existing config.dev.yaml
// style. A trailing newline is included.
//
// Empty optional fields are emitted explicitly (e.g. `auth_method: ""`)
// rather than omitted, because the source of this call is typically a
// .reg file or registry-loaded config where the empty-string distinction
// matters: re-importing a YAML config that omits a field would leave any
// previously-set value in place, whereas an explicit empty string clears
// it. This matches the clearing semantics already used by reg-export.
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
