package config

import (
	"reflect"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSocketListUnmarshalScalar(t *testing.T) {
	var v struct {
		S SocketList `yaml:"token_socket"`
	}
	if err := yaml.Unmarshal([]byte("token_socket: /run/peer/api.sock\n"), &v); err != nil {
		t.Fatal(err)
	}
	if want := (SocketList{"/run/peer/api.sock"}); !reflect.DeepEqual(v.S, want) {
		t.Errorf("got %v, want %v", v.S, want)
	}
}

// A scalar naming exactly the pre-list default is read as "the default, as it
// was written then" — the pair — not as a deliberate one-element list. Without
// this, such a host borrows once, triggers the forward rename, and then matches
// no socket at all with no borrow left to recover through.
//
// TODO(pre-1.0, #172): drop with the scalar form.
func TestSocketListUnmarshalLegacyScalarExpandsToPair(t *testing.T) {
	var v struct {
		S SocketList `yaml:"token_socket"`
	}
	if err := yaml.Unmarshal([]byte("token_socket: "+LegacyPeerSocket+"\n"), &v); err != nil {
		t.Fatal(err)
	}
	want := SocketList{LegacyPeerSocket, PerHostPeerSocketGlob}
	if !reflect.DeepEqual(v.S, want) {
		t.Errorf("got %v, want %v", v.S, want)
	}
	// Non-nil, so an exported config shows the pair in force rather than the
	// lossy absent form.
	if v.S == nil {
		t.Error("expanded list must be non-nil")
	}
}

// An explicit sequence is the operator's own words and is left alone, even when
// it happens to hold only the legacy path. The migrator's own guard is what
// keeps that host safe (cmd/dotvault canFindRenamedSocket).
func TestSocketListSequenceWithLegacyPathIsNotExpanded(t *testing.T) {
	var v struct {
		S SocketList `yaml:"token_socket"`
	}
	if err := yaml.Unmarshal([]byte("token_socket:\n  - "+LegacyPeerSocket+"\n"), &v); err != nil {
		t.Fatal(err)
	}
	if want := (SocketList{LegacyPeerSocket}); !reflect.DeepEqual(v.S, want) {
		t.Errorf("got %v, want %v", v.S, want)
	}
}

func TestExpandLegacyScalar(t *testing.T) {
	if got, want := ExpandLegacyScalar(LegacyPeerSocket), (SocketList{LegacyPeerSocket, PerHostPeerSocketGlob}); !reflect.DeepEqual(got, want) {
		t.Errorf("legacy value: got %v, want %v", got, want)
	}
	for _, other := range []string{"/run/peer/api.sock", "~/.ssh/dotvault.other.sock", "~/.ssh/dotvault.*.sock"} {
		if got, want := ExpandLegacyScalar(other), (SocketList{other}); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %v, want %v", other, got, want)
		}
	}
}

func TestSocketListUnmarshalSequence(t *testing.T) {
	var v struct {
		S SocketList `yaml:"token_socket"`
	}
	in := "token_socket:\n  - ~/.ssh/dotvault.sock\n  - ~/.ssh/dotvault.*.sock\n"
	if err := yaml.Unmarshal([]byte(in), &v); err != nil {
		t.Fatal(err)
	}
	if want := (SocketList{"~/.ssh/dotvault.sock", "~/.ssh/dotvault.*.sock"}); !reflect.DeepEqual(v.S, want) {
		t.Errorf("got %v, want %v", v.S, want)
	}
}

// An empty scalar and an empty sequence both mean "explicitly disabled":
// non-nil and empty, distinguishable from an absent key (nil).
func TestSocketListUnmarshalEmptyForms(t *testing.T) {
	for _, in := range []string{"token_socket: \"\"\n", "token_socket: []\n"} {
		var v struct {
			S SocketList `yaml:"token_socket"`
		}
		if err := yaml.Unmarshal([]byte(in), &v); err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if v.S == nil || len(v.S) != 0 {
			t.Errorf("%q: got %#v, want non-nil empty", in, v.S)
		}
	}
	var absent struct {
		S SocketList `yaml:"token_socket"`
	}
	if err := yaml.Unmarshal([]byte("other: 1\n"), &absent); err != nil {
		t.Fatal(err)
	}
	if absent.S != nil {
		t.Errorf("absent key: got %#v, want nil", absent.S)
	}
}

// The nil/empty distinction has to survive a marshal too: `reg-export` and the
// web config download both marshal the whole *config.Config, and yaml.v3's
// default rendering of a nil slice is `[]` — which re-parses as the non-nil
// empty list meaning "peer sockets explicitly disabled". So every host that
// never set the key exported a config that switched borrowing off.
func TestSocketListYAMLRoundTripPreservesNilVersusEmpty(t *testing.T) {
	type doc struct {
		S SocketList `yaml:"token_socket"`
	}
	cases := []struct {
		name    string
		in      SocketList
		wantOut string
		wantNil bool
		wantLen int
	}{
		{name: "nil stays nil", in: nil, wantOut: "token_socket: null\n", wantNil: true},
		{name: "explicit empty stays non-nil empty", in: SocketList{}, wantOut: "token_socket: []\n"},
		{
			name:    "two elements survive",
			in:      SocketList{LegacyPeerSocket, PerHostPeerSocketGlob},
			wantOut: "token_socket:\n    - " + LegacyPeerSocket + "\n    - " + PerHostPeerSocketGlob + "\n",
			wantLen: 2,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Marshalled by value, as internal/regfile hands the config over.
			out, err := yaml.Marshal(doc{S: c.in})
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != c.wantOut {
				t.Errorf("marshal: got %q, want %q", out, c.wantOut)
			}
			var back doc
			if err := yaml.Unmarshal(out, &back); err != nil {
				t.Fatal(err)
			}
			if c.wantNil {
				if back.S != nil {
					t.Fatalf("reparse: got %#v, want nil", back.S)
				}
				return
			}
			if back.S == nil {
				t.Fatal("reparse: got nil, want non-nil")
			}
			if len(back.S) != c.wantLen {
				t.Fatalf("reparse: got %#v, want %d elements", back.S, c.wantLen)
			}
			if c.wantLen > 0 && !reflect.DeepEqual(back.S, c.in) {
				t.Errorf("reparse: got %v, want %v", back.S, c.in)
			}
		})
	}
}

func TestSocketListUnmarshalRejectsMapping(t *testing.T) {
	var v struct {
		S SocketList `yaml:"token_socket"`
	}
	if err := yaml.Unmarshal([]byte("token_socket: {a: b}\n"), &v); err == nil {
		t.Fatal("expected error for mapping")
	}
}

func TestValidateSocketPattern(t *testing.T) {
	cases := []struct {
		in      string
		wantErr string
	}{
		{"~/.ssh/dotvault.sock", ""},
		{"~/.ssh/dotvault.*.sock", ""},
		{"/run/user/1000/dotvault/api.sock", ""},
		{"/tmp/dotvault-?.sock", ""},
		{"", "must not be empty"},
		{"relative/dotvault.sock", "must be an absolute path"},
		{"~user/dotvault.sock", "must be an absolute path"},
		{"~/*/dotvault.sock", "only in the final path segment"},
		{"/tmp/*/dotvault.sock", "only in the final path segment"},
		{"/tmp/dotvault\x00.sock", "NUL"},
		// .. segments are rejected wherever they appear, mirroring
		// sshfwd.ValidateRemoteSocket at the other end of the same forward. A
		// segment that merely contains ".." is an ordinary directory name.
		{"~/.ssh/../x/dotvault.sock", ".. path segments"},
		{"/tmp/../dotvault.*.sock", ".. path segments"},
		{"/tmp/a..b/dotvault.sock", ""},
	}
	for _, c := range cases {
		err := ValidateSocketPattern(c.in)
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("%q: unexpected error %v", c.in, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%q: got %v, want error containing %q", c.in, err, c.wantErr)
		}
	}
}

// A Windows pattern is backslash-separated, so the final-segment split must use
// LastIndexAny rather than LastIndex on "/" — otherwise the whole of
// `C:\foo\*\bar.sock` reads as one final segment and a directory glob is
// accepted. The rejection is asserted on every platform (the *reason* differs:
// off Windows filepath.IsAbs rejects `C:\…` as relative first), while the
// accepted spelling is only accepted where it is genuinely absolute.
func TestValidateSocketPatternWindowsSeparator(t *testing.T) {
	if err := ValidateSocketPattern(`C:\foo\*\bar.sock`); err == nil {
		t.Error(`C:\foo\*\bar.sock: got nil, want a rejection`)
	}
	err := ValidateSocketPattern(`C:\foo\dotvault.*.sock`)
	if runtime.GOOS == "windows" {
		if err != nil {
			t.Errorf(`C:\foo\dotvault.*.sock: unexpected error %v`, err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "must be an absolute path") {
		t.Errorf(`C:\foo\dotvault.*.sock off windows: got %v, want a non-absolute rejection`, err)
	}
}

func TestValidateRejectsBadTokenSocketEntry(t *testing.T) {
	cfg := minimalValidConfig()
	cfg.Vault.TokenSockets = SocketList{"relative.sock"}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "vault.token_socket") {
		t.Fatalf("got %v, want vault.token_socket validation error", err)
	}
}

func minimalValidConfig() *Config {
	return &Config{
		Vault: VaultConfig{Address: "http://127.0.0.1:8200", AuthMethod: "token"},
		Rules: []Rule{{Name: "r", VaultKey: "k", Target: Target{Path: "/tmp/x", Format: "text"}}},
	}
}
