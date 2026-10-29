package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
	"github.com/goodtune/dotvault/internal/vaultfs"
)

// memKV is an in-memory kvBackend keyed by relative path.
type memKV struct {
	secrets map[string]*vaultfs.Secret
	// casRaces makes the next n WriteCAS calls lose, simulating a concurrent
	// writer bumping the version between the read and the write.
	casRaces int
	writes   int
}

func newMemKV() *memKV { return &memKV{secrets: map[string]*vaultfs.Secret{}} }

func (m *memKV) put(rel string, data map[string]any) {
	v := 1
	if old, ok := m.secrets[rel]; ok {
		v = old.Version + 1
	}
	cp := make(map[string]any, len(data))
	for k, val := range data {
		cp[k] = val
	}
	m.secrets[rel] = &vaultfs.Secret{Data: cp, Version: v}
}

func (m *memKV) List(_ context.Context, rel string) ([]string, error) {
	prefix := ""
	if rel != "" {
		prefix = rel + "/"
	}
	seen := map[string]bool{}
	for p := range m.secrets {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := strings.TrimPrefix(p, prefix)
		if i := strings.Index(rest, "/"); i >= 0 {
			seen[rest[:i+1]] = true
		} else {
			seen[rest] = true
		}
	}
	var out []string
	for k := range seen {
		out = append(out, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out))) // the command must sort
	return out, nil
}

func (m *memKV) Read(_ context.Context, rel string) (*vaultfs.Secret, error) {
	return m.secrets[rel], nil
}

func (m *memKV) Write(_ context.Context, rel string, data map[string]any) error {
	m.writes++
	m.put(rel, data)
	return nil
}

func (m *memKV) WriteCAS(_ context.Context, rel string, data map[string]any, cas int) error {
	if m.casRaces > 0 {
		m.casRaces--
		// Another writer lands first, adding a field of its own.
		cur := m.secrets[rel]
		next := map[string]any{"other": "writer"}
		for k, v := range cur.Data {
			next[k] = v
		}
		m.put(rel, next)
		return fmt.Errorf("write: %w", vault.ErrCASMismatch)
	}
	cur := m.secrets[rel]
	if (cur == nil && cas != 0) || (cur != nil && cur.Version != cas) {
		return fmt.Errorf("write: %w", vault.ErrCASMismatch)
	}
	m.writes++
	m.put(rel, data)
	return nil
}

func (m *memKV) Delete(_ context.Context, rel string) error {
	delete(m.secrets, rel)
	return nil
}

func kvTestSession(m *memKV) *kvSession {
	return &kvSession{kv: m, cfg: &config.Config{Enrolments: map[string]config.Enrolment{"gh": {Engine: "github"}}}}
}

func TestKVList(t *testing.T) {
	m := newMemKV()
	m.put("gh", map[string]any{"oauth_token": "x"})
	m.put("databricks/prod", map[string]any{"access_token": "y"})
	m.put("databricks/dev", map[string]any{"access_token": "z"})
	s := kvTestSession(m)

	var out bytes.Buffer
	if err := kvList(context.Background(), s, &out, "", "table"); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "databricks/\ngh\n"; got != want {
		t.Errorf("root listing = %q, want %q", got, want)
	}

	out.Reset()
	if err := kvList(context.Background(), s, &out, "databricks/", "json"); err != nil {
		t.Fatal(err)
	}
	var keys []string
	if err := json.Unmarshal(out.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	if strings.Join(keys, ",") != "dev,prod" {
		t.Errorf("folder listing = %v", keys)
	}

	if err := kvList(context.Background(), s, &out, "nope", "table"); err == nil {
		t.Error("empty folder should be an error")
	}
	if err := kvList(context.Background(), s, &out, "a/../b", "table"); err == nil {
		t.Error("non-canonical path should be refused")
	}
}

func TestKVGet(t *testing.T) {
	m := newMemKV()
	m.put("ssh", map[string]any{"private_key": "-----BEGIN-----\nabc\n", "n": json.Number("1000000"), "pub": "ssh-ed25519 AAA"})
	s := kvTestSession(m)
	ctx := context.Background()

	var out bytes.Buffer
	if err := kvGet(ctx, s, &out, "ssh", "private_key", "table", false); err != nil {
		t.Fatal(err)
	}
	if out.String() != "-----BEGIN-----\nabc\n" {
		t.Errorf("field output not verbatim: %q", out.String())
	}

	out.Reset()
	if err := kvGet(ctx, s, &out, "ssh", "pub", "table", false); err != nil {
		t.Fatal(err)
	}
	if out.String() != "ssh-ed25519 AAA" {
		t.Errorf("non-tty field output should carry no added newline: %q", out.String())
	}
	out.Reset()
	if err := kvGet(ctx, s, &out, "ssh", "pub", "table", true); err != nil {
		t.Fatal(err)
	}
	if out.String() != "ssh-ed25519 AAA\n" {
		t.Errorf("tty field output should end in a newline: %q", out.String())
	}

	out.Reset()
	if err := kvGet(ctx, s, &out, "ssh", "n", "table", false); err != nil {
		t.Fatal(err)
	}
	if out.String() != "1000000" {
		t.Errorf("number field = %q", out.String())
	}

	out.Reset()
	if err := kvGet(ctx, s, &out, "ssh", "", "json", false); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc["pub"] != "ssh-ed25519 AAA" {
		t.Errorf("json output = %q (%v)", out.String(), err)
	}

	out.Reset()
	if err := kvGet(ctx, s, &out, "ssh", "", "table", false); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "Key") || !strings.Contains(out.String(), "pub ") {
		t.Errorf("table output = %q", out.String())
	}

	for _, tc := range []struct{ path, field, format string }{
		{"missing", "", "table"},
		{"ssh", "absent", "table"},
		{"", "", "table"},
		{"ssh", "", "yaml"},
		{"ssh", "pub", "json"},
		{"ssh/", "", "table"},
		{`dir\ssh`, "", "table"},
	} {
		if err := kvGet(ctx, s, &out, tc.path, tc.field, tc.format, false); err == nil {
			t.Errorf("get %+v: want error", tc)
		}
	}
}

func TestKVPutReplacesAndGuardsEnrolments(t *testing.T) {
	m := newMemKV()
	m.put("personal/api", map[string]any{"old": "gone", "token": "a"})
	s := kvTestSession(m)
	ctx := context.Background()
	var log bytes.Buffer

	if err := kvPut(ctx, s, &log, "personal/api", map[string]any{"token": "b"}, false, false); err != nil {
		t.Fatal(err)
	}
	if got := m.secrets["personal/api"].Data; len(got) != 1 || got["token"] != "b" {
		t.Errorf("put should replace the whole secret, got %v", got)
	}
	if !strings.Contains(log.String(), "1 field to personal/api") {
		t.Errorf("unexpected confirmation %q", log.String())
	}

	if err := kvPut(ctx, s, &log, "gh", map[string]any{"oauth_token": "x"}, false, false); err == nil {
		t.Error("write to an enrolment path should be refused without --force")
	}
	if err := kvPut(ctx, s, &log, "gh", map[string]any{"oauth_token": "x"}, true, false); err != nil {
		t.Errorf("--force should allow the write: %v", err)
	}

	before := m.writes
	if err := kvPut(ctx, s, &log, "new", map[string]any{"k": "v"}, false, true); err != nil {
		t.Fatal(err)
	}
	if m.writes != before || m.secrets["new"] != nil {
		t.Error("dry run must not write")
	}
}

func TestKVPatch(t *testing.T) {
	ctx := context.Background()
	var log bytes.Buffer

	t.Run("merges and removes", func(t *testing.T) {
		m := newMemKV()
		m.put("x", map[string]any{"a": "1", "b": "2", "n": json.Number("7")})
		s := kvTestSession(m)
		if err := kvPatch(ctx, s, &log, "x", map[string]any{"a": "9", "c": "3"}, []string{"b"}, false, false); err != nil {
			t.Fatal(err)
		}
		got := m.secrets["x"].Data
		if got["a"] != "9" || got["c"] != "3" || got["n"] != json.Number("7") {
			t.Errorf("patched = %v", got)
		}
		if _, ok := got["b"]; ok {
			t.Error("b should be removed")
		}
	})

	t.Run("re-applies after losing a CAS race", func(t *testing.T) {
		m := newMemKV()
		m.put("x", map[string]any{"a": "1"})
		m.casRaces = 1
		s := kvTestSession(m)
		if err := kvPatch(ctx, s, &log, "x", map[string]any{"a": "2"}, nil, false, false); err != nil {
			t.Fatal(err)
		}
		got := m.secrets["x"].Data
		if got["a"] != "2" || got["other"] != "writer" {
			t.Errorf("concurrent writer's field lost or patch not applied: %v", got)
		}
	})

	t.Run("gives up after repeated races", func(t *testing.T) {
		m := newMemKV()
		m.put("x", map[string]any{"a": "1"})
		m.casRaces = kvCASAttempts
		s := kvTestSession(m)
		m.casRaces = kvCASAttempts + 1
		err := kvPatch(ctx, s, &log, "x", map[string]any{"a": "2"}, nil, false, false)
		if !errors.Is(err, vault.ErrCASMismatch) {
			t.Errorf("err = %v, want ErrCASMismatch", err)
		}
		if m.casRaces != 1 {
			t.Errorf("made %d CAS attempts, want %d", kvCASAttempts+1-m.casRaces, kvCASAttempts)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		m := newMemKV()
		m.put("x", map[string]any{"a": "1"})
		s := kvTestSession(m)
		cases := []struct {
			name   string
			path   string
			set    map[string]any
			remove []string
		}{
			{"absent secret", "y", map[string]any{"a": "1"}, nil},
			{"remove missing field", "x", nil, []string{"zz"}},
			{"remove last field", "x", nil, []string{"a"}},
			{"set and remove", "x", map[string]any{"a": "2"}, []string{"a"}},
			{"enrolment path", "gh", map[string]any{"a": "1"}, nil},
			{"duplicate remove", "x", map[string]any{"b": "1"}, []string{"a", "a"}},
		}
		for _, tc := range cases {
			if err := kvPatch(ctx, s, &log, tc.path, tc.set, tc.remove, false, false); err == nil {
				t.Errorf("%s: want error", tc.name)
			}
		}
		if m.writes != 0 {
			t.Errorf("refused patches wrote %d times", m.writes)
		}
	})
}

func TestKVDelete(t *testing.T) {
	m := newMemKV()
	m.put("x", map[string]any{"a": "1"})
	m.put("gh", map[string]any{"oauth_token": "t"})
	s := kvTestSession(m)
	ctx := context.Background()
	var log bytes.Buffer

	if err := kvDelete(ctx, s, &log, "x", false, true); err != nil || m.secrets["x"] == nil {
		t.Fatalf("dry run deleted or failed: %v", err)
	}
	if err := kvDelete(ctx, s, &log, "x", false, false); err != nil {
		t.Fatal(err)
	}
	if m.secrets["x"] != nil {
		t.Error("secret not deleted")
	}
	if err := kvDelete(ctx, s, &log, "x", false, false); err == nil {
		t.Error("deleting an absent secret should be an error")
	}
	if err := kvDelete(ctx, s, &log, "gh", false, false); err == nil {
		t.Error("deleting an enrolment secret should need --force")
	}
	if err := kvDelete(ctx, s, &log, "gh", true, false); err != nil || m.secrets["gh"] != nil {
		t.Errorf("--force delete: %v", err)
	}
}

func TestParseKVData(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("PEM\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := parseKVData([]string{"a=1", "b=x=y", "c=@" + keyFile, "d=-", "e="}, strings.NewReader("from stdin\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	// @file is verbatim; stdin loses exactly one trailing newline.
	want := map[string]any{"a": "1", "b": "x=y", "c": "PEM\n", "d": "from stdin", "e": ""}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}

	doc, err := parseKVData([]string{"-"}, strings.NewReader(`{"n": 1000000, "s": "v"}`))
	if err != nil {
		t.Fatal(err)
	}
	if doc["n"] != json.Number("1000000") || doc["s"] != "v" {
		t.Errorf("json document = %v", doc)
	}

	for _, args := range [][]string{
		{"novalue"},
		{"=v"},
		{"a=1", "a=2"},
		{"a=-", "b=-"},
		{"a=1", "-"},
		{"a=@" + filepath.Join(dir, "missing")},
	} {
		if _, err := parseKVData(args, strings.NewReader("x")); err == nil {
			t.Errorf("%v: want error", args)
		}
	}

	if _, err := parseKVData([]string{"-"}, strings.NewReader(`[1]`)); err == nil {
		t.Error("a non-object document should be refused")
	}
	if _, err := parseKVData([]string{"a=-"}, bytes.NewReader(make([]byte, kvMaxInput+1))); err == nil {
		t.Error("oversized stdin should be refused")
	}

	// Errors must not quote the value: it is a credential.
	_, err = parseKVData([]string{"s3cr3t-value"}, nil)
	if err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("error leaks the argument: %v", err)
	}
}

func TestKVCommandWiring(t *testing.T) {
	m := newMemKV()
	m.put("gh", map[string]any{"oauth_token": "tok"})
	orig := openKVSession
	openKVSession = func(context.Context) (*kvSession, error) { return kvTestSession(m), nil }
	t.Cleanup(func() { openKVSession = orig })

	cmd := newKVCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetIn(strings.NewReader("piped"))
	cmd.SetArgs([]string{"put", "personal/api", "token=-"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if m.secrets["personal/api"].Data["token"] != "piped" {
		t.Errorf("put via command = %v", m.secrets["personal/api"].Data)
	}

	cmd = newKVCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"get", "--field", "token", "personal/api"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if out.String() != "piped" {
		t.Errorf("get via command = %q", out.String())
	}
}

// TestVaultKVPaths pins how the store the kv commands drive composes Vault paths: everything sits
// under the mount and the user's root, on the data/ or metadata/ endpoint
// each operation needs.
func TestVaultKVPaths(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.Method
		if r.URL.Query().Get("list") == "true" {
			method = "LIST"
		}
		seen = append(seen, method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case method == "LIST":
			fmt.Fprint(w, `{"data":{"keys":["a","b/"]}}`)
		case r.Method == http.MethodGet:
			fmt.Fprint(w, `{"data":{"data":{"k":"v"},"metadata":{"version":3}}}`)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			fmt.Fprint(w, `{"data":{"version":4}}`)
		}
	}))
	defer srv.Close()

	vc, err := vault.NewClient(vault.Config{Address: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	vc.SetToken("t")
	store, err := vaultfs.NewStore(vc, "kv", "users/", "alice")
	if err != nil {
		t.Fatal(err)
	}
	k, ok := store.(kvBackend)
	if !ok {
		t.Fatal("vault store does not satisfy kvBackend (no WriteCAS)")
	}
	ctx := context.Background()

	if _, err := k.List(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := k.List(ctx, "databricks"); err != nil {
		t.Fatal(err)
	}
	sec, err := k.Read(ctx, "gh")
	if err != nil || sec.Version != 3 || sec.Data["k"] != "v" {
		t.Fatalf("read = %+v, %v", sec, err)
	}
	if err := k.Write(ctx, "gh", map[string]any{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	if err := k.WriteCAS(ctx, "gh", map[string]any{"k": "v"}, 3); err != nil {
		t.Fatal(err)
	}
	if err := k.Delete(ctx, "gh"); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"LIST /v1/kv/metadata/users/alice",
		"LIST /v1/kv/metadata/users/alice/databricks",
		"GET /v1/kv/data/users/alice/gh",
		"PUT /v1/kv/data/users/alice/gh",
		"PUT /v1/kv/data/users/alice/gh",
		"DELETE /v1/kv/metadata/users/alice/gh",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests:\n%s\nwant:\n%s", strings.Join(seen, "\n"), strings.Join(want, "\n"))
	}
}

func TestKVClipboard(t *testing.T) {
	m := newMemKV()
	m.put("single", map[string]any{"token": "tok-1\n"})
	m.put("multi", map[string]any{"a": "1", "b": "2"})
	m.put("bad", map[string]any{"v": "nul\x00byte"})
	s := kvTestSession(m)
	ctx := context.Background()

	var got []string
	orig := kvDeliverClipboard
	kvDeliverClipboard = func(_ context.Context, cfg *config.Config, text string) error {
		if cfg != s.cfg {
			t.Error("delivery should use the session's config (it carries the peer sockets)")
		}
		got = append(got, text)
		return nil
	}
	t.Cleanup(func() { kvDeliverClipboard = orig })

	// A single-field secret needs no --field; one trailing newline is
	// dropped, as `kv get --field … | dotvault clipboard` would.
	if err := kvClipboard(ctx, s, "single", ""); err != nil {
		t.Fatal(err)
	}
	if err := kvClipboard(ctx, s, "multi", "b"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "|") != "tok-1|2" {
		t.Errorf("delivered %q", got)
	}

	got = nil
	err := kvClipboard(ctx, s, "multi", "")
	if err == nil || !strings.Contains(err.Error(), "a, b") {
		t.Errorf("ambiguous field: err = %v", err)
	}
	for _, tc := range []struct{ path, field string }{{"missing", ""}, {"multi", "zz"}, {"bad", ""}, {"", ""}} {
		if err := kvClipboard(ctx, s, tc.path, tc.field); err == nil {
			t.Errorf("%+v: want error", tc)
		}
	}
	if len(got) != 0 {
		t.Errorf("refused copies still delivered %q", got)
	}
}

// TestDeliverClipboardFallsBackLocally pins the shared delivery path: with
// no live peer, the text lands on the local clipboard.
func TestDeliverClipboardFallsBackLocally(t *testing.T) {
	var local string
	orig := setLocalClipboard
	setLocalClipboard = func(text string) error { local = text; return nil }
	t.Cleanup(func() { setLocalClipboard = orig })

	cfg := &config.Config{Vault: config.VaultConfig{TokenSockets: []string{filepath.Join(t.TempDir(), "absent.sock")}}}
	if err := deliverClipboard(context.Background(), cfg, "v"); err != nil {
		t.Fatal(err)
	}
	if local != "v" {
		t.Errorf("local clipboard = %q", local)
	}
	local = ""
	if err := deliverClipboard(context.Background(), nil, "w"); err != nil || local != "w" {
		t.Errorf("nil config: local = %q, err = %v", local, err)
	}
}

func TestKVTableOutputEscapesControls(t *testing.T) {
	m := newMemKV()
	m.put("x", map[string]any{"v": "a\x1b]52;c;ZXZpbA==\x07b"})
	s := kvTestSession(m)
	var out bytes.Buffer
	m.put("pem", map[string]any{"k": "line1\nline2"})
	if err := kvGet(context.Background(), s, &out, "x", "", "table", false); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(out.String(), 0x1b) || !strings.Contains(out.String(), `\x1b`) {
		t.Errorf("table output not escaped: %q", out.String())
	}
	out.Reset()
	if err := kvGet(context.Background(), s, &out, "pem", "", "table", false); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "\n") != 3 || !strings.Contains(out.String(), `line1\nline2`) {
		t.Errorf("multi-line value should stay on its row: %q", out.String())
	}
	out.Reset()
	if err := kvGet(context.Background(), s, &out, "x", "v", "table", true); err != nil {
		t.Fatal(err)
	}
	if !strings.ContainsRune(out.String(), 0x1b) {
		t.Error("--field output must stay byte for byte")
	}
}

func TestEditPolicyManagedMatchesGuard(t *testing.T) {
	s := kvTestSession(newMemKV())
	if err := guardManaged(s.cfg, "gh", false); err == nil {
		t.Error("enrolment path not guarded")
	}
	if err := guardManaged(s.cfg, "gh/sub", false); err != nil {
		t.Errorf("path below an enrolment is not itself managed: %v", err)
	}
}
