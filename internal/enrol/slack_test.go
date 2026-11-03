package enrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goodtune/dotvault/internal/vault"
)

func slackSettings(ws ...string) map[string]any {
	list := make([]any, len(ws))
	for i, w := range ws {
		list[i] = w
	}
	return map[string]any{"workspaces": list}
}

func pasteIO(paste string) IO {
	return IO{
		Out:          &bytes.Buffer{},
		PromptSecret: func(string) (string, error) { return paste, nil },
	}
}

func decodeCred(t *testing.T, s string) SlackCredential {
	t.Helper()
	var c SlackCredential
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		t.Fatalf("field is not a SlackCredential: %v (%q)", err, s)
	}
	return c
}

func TestSlackRunStoresTheCookieForEveryWorkspace(t *testing.T) {
	curl := `curl 'https://acme.slack.com/api/client.counts' -H 'cookie: b=x; d=xoxd-good; d-s=1' --data-raw 'token=xoxc-old'`
	out, err := (&SlackEngine{}).Run(context.Background(), slackSettings("acme", "beta"), pasteIO(curl))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("out = %v, want exactly the two workspace fields", out)
	}
	for _, d := range []string{"acme", "beta"} {
		if c := decodeCred(t, out[d]); c != (SlackCredential{Domain: d, Cookie: "xoxd-good"}) {
			t.Errorf("%s = %+v", d, c)
		}
		// The contract with slk: no access token, which slk mints itself.
		if strings.Contains(out[d], "access_token") || strings.Contains(out[d], "xoxc-") {
			t.Errorf("%s carries a token: %q", d, out[d])
		}
	}
	// The field set the manager checks for completeness is the workspaces.
	if got := (&SlackEngine{}).FieldsFromSettings(slackSettings("acme", "beta")); strings.Join(got, ",") != "acme,beta" {
		t.Errorf("FieldsFromSettings = %v", got)
	}
}

func TestSlackRunEnterpriseGrid(t *testing.T) {
	out, err := (&SlackEngine{}).Run(context.Background(), slackSettings("company.enterprise"), pasteIO("xoxd-g"))
	if err != nil {
		t.Fatal(err)
	}
	if c := decodeCred(t, out["company.enterprise"]); c != (SlackCredential{Domain: "company.enterprise", Cookie: "xoxd-g"}) {
		t.Errorf("credential = %+v", c)
	}
}

func TestSlackRunMergesTheExistingSecret(t *testing.T) {
	fv := newFakeVault("kv")
	fv.secrets["users/u/slack/slk"] = map[string]string{
		"gone": `{"domain":"gone","cookie":"xoxd-old"}`,
		"note": "written by hand",
		"acme": `{"domain":"acme","cookie":"xoxd-stale"}`,
	}
	eio := pasteIO("xoxd-good")
	eio.Vault, eio.KVMount, eio.TargetPath = fv.serve(t), "kv", "users/u/slack/slk"
	out, err := (&SlackEngine{}).Run(context.Background(), slackSettings("acme"), eio)
	if err != nil {
		t.Fatal(err)
	}
	if decodeCred(t, out["acme"]).Cookie != "xoxd-good" {
		t.Errorf("acme not replaced with the new session: %v", out)
	}
	if out["note"] != "written by hand" || !strings.Contains(out["gone"], "xoxd-old") {
		t.Errorf("fields this run does not write must be kept: %v", out)
	}
}

func TestSlackRunNeedsACookie(t *testing.T) {
	e := &SlackEngine{}
	if _, err := e.Run(context.Background(), slackSettings("acme"), pasteIO("just some text")); err == nil || !strings.Contains(err.Error(), "no d cookie") {
		t.Fatalf("err = %v", err)
	}
	if _, err := e.Run(context.Background(), slackSettings("acme"), IO{}); err == nil || !strings.Contains(err.Error(), "PromptSecret") {
		t.Fatalf("no PromptSecret: err = %v", err)
	}
	failing := IO{PromptSecret: func(string) (string, error) { return "", errors.New("cancelled") }}
	if out, err := e.Run(context.Background(), slackSettings("acme"), failing); err == nil || out != nil {
		t.Fatalf("prompt error: out = %v, err = %v", out, err)
	}
	// No Out at all is fine: nothing to print to.
	quiet := IO{PromptSecret: func(string) (string, error) { return "xoxd-good", nil }}
	if out, err := e.Run(context.Background(), slackSettings("acme"), quiet); err != nil || decodeCred(t, out["acme"]).Cookie != "xoxd-good" {
		t.Fatalf("nil Out: out = %v, err = %v", out, err)
	}
	if _, err := e.Run(context.Background(), map[string]any{}, pasteIO("xoxd-good")); err == nil {
		t.Fatal("no workspaces: want an error")
	}
}

func TestSlackRunFailsWhenTheSecretCannotBeRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	vc, err := vault.NewClient(vault.Config{Address: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	vc.SetToken("t")
	eio := pasteIO("xoxd-good")
	eio.Vault, eio.KVMount, eio.TargetPath = vc, "kv", "users/u/slack/slk"
	// Writing without the existing fields would drop them, so nothing is written.
	if out, err := (&SlackEngine{}).Run(context.Background(), slackSettings("acme"), eio); err == nil || out != nil {
		t.Fatalf("out = %v, err = %v", out, err)
	}
}

func TestStringifyField(t *testing.T) {
	for in, want := range map[any]string{"plain": "plain", true: "true", 3.5: "3.5"} {
		if got := stringifyField(in); got != want {
			t.Errorf("stringifyField(%v) = %q, want %q", in, got, want)
		}
	}
	if got := stringifyField(map[string]any{"a": 1}); got != `{"a":1}` {
		t.Errorf("object = %q, want JSON", got)
	}
}

func TestSlackEngineIsNotARefresher(t *testing.T) {
	// There is no token to rotate: slk mints its own from the cookie.
	if _, ok := any(&SlackEngine{}).(Refresher); ok {
		t.Error("the slack engine must not refresh anything")
	}
}

func TestParseSlackCookie(t *testing.T) {
	cases := map[string]string{
		"bash curl":   `curl 'https://x.slack.com/api/a' -H 'cookie: b=1; d=xoxd-abc%2Fdef; x=2'`,
		"cmd curl":    `curl ^"https://x.slack.com/api/a^" -H ^"cookie: d=xoxd-abc%2Fdef; x=2^"`,
		"powershell":  `$session.Cookies.Add((New-Object System.Net.Cookie("d", "xoxd-abc%2Fdef", "/", ".slack.com")))`,
		"pair":        `d=xoxd-abc%2Fdef`,
		"bare":        "  xoxd-abc%2Fdef  ",
		"decoded":     "xoxd-abc/def",
		"bare + semi": "xoxd-abc%2Fdef;",
		"bare CRLF":   "\r\nxoxd-abc%2Fdef\r\n",
		"ps + space":  `New-Object System.Net.Cookie("d", "xoxd-abc%2Fdef", "/", ".slack.com")`,
		// Chrome's Copy as cURL (cmd) escapes % as ^%.
		"cmd escaped %": `curl ^"https://x.slack.com/api/a^" -H ^"cookie: d=xoxd-abc^%^2Fdef; x=2^"`,
		// A web form input drops the newlines of a multi-line paste.
		"joined lines": `curl 'https://x.slack.com/api/a' \  -H 'cookie: d=xoxd-abc%2Fdef' \  --data-raw 'x'`,
	}
	for name, paste := range cases {
		if got := parseSlackCookie(paste); got != "xoxd-abc%2Fdef" {
			t.Errorf("%s: got %q", name, got)
		}
	}
	if got := parseSlackCookie("ds=xoxd-nope"); got != "" {
		t.Errorf("a cookie merely ending in d must not match, got %q", got)
	}
}
