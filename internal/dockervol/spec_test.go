package dockervol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestParseOptionsDefaults(t *testing.T) {
	spec, err := ParseOptions(nil, time.Minute)
	if err != nil {
		t.Fatalf("ParseOptions: %v", err)
	}
	if spec.Layout != LayoutJSON || spec.Mode != DefaultMode || spec.TTL != time.Minute || len(spec.Secrets) != 0 {
		t.Errorf("defaults = %+v", spec)
	}
	if !spec.Covers("anything/at/all") {
		t.Error("an empty selection must cover the whole subtree")
	}
}

func TestParseOptionsSelection(t *testing.T) {
	spec, err := ParseOptions(map[string]string{OptSecrets: " jfrog, databricks/ ,gh,gh"}, time.Minute)
	if err != nil {
		t.Fatalf("ParseOptions: %v", err)
	}
	want := []string{"databricks/", "gh", "jfrog"}
	if strings.Join(spec.Secrets, ",") != strings.Join(want, ",") {
		t.Errorf("Secrets = %v, want %v (sorted, deduplicated)", spec.Secrets, want)
	}
	for path, covered := range map[string]bool{
		"gh":              true,
		"gh/sub":          false, // a bare name is one secret, not a folder
		"databricks":      false, // the folder's own name is a different secret, which render never emits
		"databricks/prod": true,
		"databricksx":     false,
		"other":           false,
	} {
		if got := spec.Covers(path); got != covered {
			t.Errorf("Covers(%q) = %v, want %v", path, got, covered)
		}
	}
}

func TestParseOptionsRejects(t *testing.T) {
	for name, opts := range map[string]map[string]string{
		"unknown option":         {"secret": "gh"},
		"bad layout":             {OptLayout: "yaml"},
		"non-octal mode":         {OptMode: "rw"},
		"write bit":              {OptMode: "0600"},
		"no owner read":          {OptMode: "0044"},
		"zero mode":              {OptMode: "0"},
		"ttl zero":               {OptTTL: "0"},
		"ttl over ceiling":       {OptTTL: "1h"},
		"ttl unparseable":        {OptTTL: "soon"},
		"path traversal":         {OptSecrets: "../other"},
		"bare slash":             {OptSecrets: "/"},
		"embedded empty segment": {OptSecrets: "a//b"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseOptions(opts, time.Minute); err == nil {
				t.Errorf("ParseOptions(%v) accepted", opts)
			}
		})
	}
	if _, err := ParseOptions(nil, 0); err == nil {
		t.Error("ParseOptions accepted no ttl at all")
	}
}

func TestParseOptionsModeAndTTL(t *testing.T) {
	spec, err := ParseOptions(map[string]string{OptMode: "0444", OptTTL: "30s", OptLayout: "fields"}, time.Minute)
	if err != nil {
		t.Fatalf("ParseOptions: %v", err)
	}
	if spec.Mode != 0o444 || spec.TTL != 30*time.Second || spec.Layout != LayoutFields {
		t.Errorf("spec = %+v", spec)
	}
	if got := spec.DirMode(); got != 0o755 {
		t.Errorf("DirMode() = %o, want 0755 so a reader granted read can traverse", got)
	}
	if got := (Spec{Mode: 0o400}).DirMode(); got != 0o700 {
		t.Errorf("DirMode() = %o, want 0700 for owner-only files", got)
	}
	if got := (Spec{Mode: 0o440}).DirMode(); got != 0o750 {
		t.Errorf("DirMode() = %o, want 0750", got)
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"a", "my-vol.1_x", "0abc"} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("ValidateName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-lead", "a/b", "..", "a b", strings.Repeat("x", 256)} {
		if err := ValidateName(bad); err == nil {
			t.Errorf("ValidateName(%q) accepted", bad)
		}
	}
}

func TestSpecEqualIgnoresOrderButNotContent(t *testing.T) {
	a, _ := ParseOptions(map[string]string{OptSecrets: "b,a"}, time.Minute)
	b, _ := ParseOptions(map[string]string{OptSecrets: "a,b"}, time.Minute)
	c, _ := ParseOptions(map[string]string{OptSecrets: "a"}, time.Minute)
	if !a.Equal(b) {
		t.Error("same selection in a different order must compare equal")
	}
	if a.Equal(c) {
		t.Error("different selections must not compare equal")
	}
}

func TestParseOptionsClientCert(t *testing.T) {
	for name, tc := range map[string]struct {
		opts    map[string]string
		want    ClientCertMode
		wantErr string
	}{
		"absent":         {opts: nil, want: ClientCertOff},
		"true":           {opts: map[string]string{OptClientCert: "true"}, want: ClientCertWith},
		"only":           {opts: map[string]string{OptClientCert: "only"}, want: ClientCertOnly},
		"false":          {opts: map[string]string{OptClientCert: "false"}, want: ClientCertOff},
		"garbage":        {opts: map[string]string{OptClientCert: "yes"}, wantErr: "true, false, only"},
		"empty":          {opts: map[string]string{OptClientCert: ""}, wantErr: "true, false, only"},
		"only + secrets": {opts: map[string]string{OptClientCert: "only", OptSecrets: "gh"}, wantErr: "conflicts"},
		"true + secrets": {opts: map[string]string{OptClientCert: "true", OptSecrets: "gh"}, want: ClientCertWith},
	} {
		t.Run(name, func(t *testing.T) {
			spec, err := ParseOptions(tc.opts, time.Minute)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ParseOptions(%v) err = %v, want one containing %q", tc.opts, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseOptions(%v): %v", tc.opts, err)
			}
			if spec.ClientCert != tc.want {
				t.Errorf("ClientCert = %q, want %q", spec.ClientCert, tc.want)
			}
		})
	}
}

func TestParseOptionsUnknownListsClientCert(t *testing.T) {
	_, err := ParseOptions(map[string]string{"bogus": "1"}, time.Minute)
	if err == nil || !strings.Contains(err.Error(), OptClientCert) {
		t.Errorf("unknown-option error = %v, want the accepted list to include %s", err, OptClientCert)
	}
}

func TestClientCertOnlyCoversNothing(t *testing.T) {
	spec, err := ParseOptions(map[string]string{OptClientCert: "only"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Covers("gh") {
		t.Error("client_cert=only selects no secrets, so no Vault event concerns it")
	}
}

func TestSpecEqualDistinguishesClientCert(t *testing.T) {
	a, _ := ParseOptions(nil, time.Minute)
	b, _ := ParseOptions(map[string]string{OptClientCert: "true"}, time.Minute)
	c, _ := ParseOptions(map[string]string{OptClientCert: "false"}, time.Minute)
	if a.Equal(b) {
		t.Error("a volume with the certificate equals one without")
	}
	if !a.Equal(c) {
		t.Error("client_cert=false must equal the option being absent")
	}
}

func TestSpecValidateClientCertRoundTrip(t *testing.T) {
	spec, err := ParseOptions(map[string]string{OptClientCert: "only"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	var back Spec
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if err := back.validate(); err != nil {
		t.Fatalf("validate after reload: %v", err)
	}
	if back.ClientCert != ClientCertOnly {
		t.Errorf("reloaded ClientCert = %q", back.ClientCert)
	}

	off, _ := ParseOptions(nil, time.Minute)
	raw, _ = json.Marshal(off)
	if strings.Contains(string(raw), "client_cert") {
		t.Errorf("an off volume persists client_cert: %s", raw)
	}
	// A volume persisted before the option existed has no such key.
	var legacy Spec
	if err := json.Unmarshal([]byte(`{"layout":"json","mode":256,"ttl":60000000000}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.ClientCert != ClientCertOff || legacy.validate() != nil {
		t.Errorf("legacy spec = %+v, validate = %v", legacy, legacy.validate())
	}
	if err := (Spec{Layout: LayoutJSON, Mode: 0o400, TTL: time.Minute, ClientCert: "bogus"}).validate(); err == nil {
		t.Error("validate accepted an unknown client_cert mode")
	}
}
