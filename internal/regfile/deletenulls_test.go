package regfile

import (
	"reflect"
	"strings"
	"testing"
)

// TestRuleDeleteNullsRoundTrip pins target.delete_nulls across the .reg
// surfaces. It is emitted as a REG_DWORD under Rules\{Name}, in both the
// plain-text and the canonical UTF-16 encodings.
//
// The false case matters as much as the true one: writeBool emits the value
// even when zero, so re-importing an export clears a delete_nulls a previous
// policy set rather than leaving the stale registry value in place.
func TestRuleDeleteNullsRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name        string
		format      string
		deleteNulls bool
	}{
		{"json with delete_nulls", "json", true},
		{"yaml with delete_nulls", "yaml", true},
		{"json without delete_nulls", "json", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := validBaseConfig()
			src.Rules[0].Target.Format = tc.format
			src.Rules[0].Target.DeleteNulls = tc.deleteNulls

			text, err := GenerateText(src)
			if err != nil {
				t.Fatalf("GenerateText: %v", err)
			}
			got, err := Parse([]byte(text))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(got.Rules, src.Rules) {
				t.Errorf("Rules mismatch:\ngot:  %+v\nwant: %+v", got.Rules, src.Rules)
			}

			data, err := Generate(src)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			got, err = Parse(data)
			if err != nil {
				t.Fatalf("Parse (utf16): %v", err)
			}
			if !reflect.DeepEqual(got.Rules, src.Rules) {
				t.Errorf("Rules mismatch (utf16):\ngot:  %+v\nwant: %+v", got.Rules, src.Rules)
			}
		})
	}
}

// TestRuleDeleteNullsEmittedAsDWORD pins the registry value name and type,
// which is the contract an admin authoring policy by hand depends on.
func TestRuleDeleteNullsEmittedAsDWORD(t *testing.T) {
	src := validBaseConfig()
	src.Rules[0].Target.Format = "json"
	src.Rules[0].Target.DeleteNulls = true

	text, err := GenerateText(src)
	if err != nil {
		t.Fatalf("GenerateText: %v", err)
	}
	const want = `"TargetDeleteNulls"=dword:00000001`
	if !strings.Contains(text, want) {
		t.Errorf("output missing %q:\n%s", want, text)
	}
}
