package enrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/goodtune/dotvault/internal/config"
)

var (
	_ Engine          = (*SlackEngine)(nil)
	_ SettingsFielder = (*SlackEngine)(nil)
)

// SlackEngine enrols a Slack browser session for slk
// (docs/superpowers/specs/2026-11-03-slack-enrolment-design.md). It carries
// the session's d cookie and nothing else: the user pastes the session once,
// and the engine writes one field per configured workspace (named by its
// subdomain) holding a SlackCredential as JSON. It never contacts Slack. slk
// mints the xoxc access token from the cookie itself, in memory, every time it
// starts, so there is no token here to mint, store or refresh.
//
// The field names and the JSON shape are the contract with slk, which reads
// them through the client facade. Nothing here imports slk: slk imports
// dotvault, so the reverse would make the two modules depend on each other.
type SlackEngine struct{}

// SlackCredential is one workspace's field in a slack enrolment's secret.
type SlackCredential struct {
	Domain string `json:"domain"` // the subdomain: acme for acme.slack.com
	Cookie string `json:"cookie"` // the d cookie, URL-encoded
}

func (e *SlackEngine) Name() string { return "Slack" }

// Fields has no static answer: the written fields are the configured
// workspaces. See FieldsFromSettings.
func (e *SlackEngine) Fields() []string { return nil }

// FieldsFromSettings returns the configured workspace names, so an enrolment
// is incomplete until every listed workspace has a field, and listing a new
// one brings the enrolment back as pending. Malformed settings return nil,
// which the manager reads as incomplete.
func (e *SlackEngine) FieldsFromSettings(settings map[string]any) []string {
	ws, err := config.SlackWorkspaces(settings)
	if err != nil {
		return nil
	}
	return ws
}

// slackPastePrompt is the PromptSecret label. The web card renders it as a
// secret input, so it must stand on its own.
const slackPastePrompt = "Paste your Slack browser session (DevTools → Network → a request to /api/ → Copy as cURL, or Copy as PowerShell), or just the d cookie (xoxd-…):"

// Run asks for the browser session once and writes its d cookie for every
// configured workspace: one cookie covers every workspace that browser is
// signed in to. Fields already in the secret that this run does not write (a
// workspace no longer listed, anything another tool wrote) are kept, because
// the manager writes an engine's output as the whole secret.
//
// The cookie is not checked against Slack: that would mean minting a token,
// which is slk's job. A wrong or signed-out cookie shows up when slk starts,
// as a warning naming the workspace.
func (e *SlackEngine) Run(ctx context.Context, settings map[string]any, eio IO) (map[string]string, error) {
	workspaces, err := config.SlackWorkspaces(settings)
	if err != nil {
		return nil, fmt.Errorf("slack: settings.%w", err)
	}
	if eio.PromptSecret == nil {
		return nil, errors.New("slack: no way to ask for the browser session (PromptSecret is nil)")
	}

	out := make(map[string]string)
	if eio.Vault != nil && eio.TargetPath != "" {
		existing, err := eio.Vault.ReadKVv2(ctx, eio.KVMount, eio.TargetPath)
		if err != nil {
			return nil, fmt.Errorf("slack: read %s/%s: %w", eio.KVMount, eio.TargetPath, err)
		}
		if existing != nil {
			for k, v := range existing.Data {
				out[k] = stringifyField(v)
			}
		}
	}

	paste, err := eio.PromptSecret(slackPastePrompt)
	if err != nil {
		return nil, fmt.Errorf("slack: read session: %w", err)
	}
	cookie := parseSlackCookie(paste)
	if cookie == "" {
		return nil, errors.New("slack: no d cookie (xoxd-…) found in what was pasted; copy a request to /api/ as cURL, or the d cookie from DevTools → Application → Cookies")
	}

	for _, domain := range workspaces {
		b, err := json.Marshal(SlackCredential{Domain: domain, Cookie: cookie})
		if err != nil {
			return nil, err
		}
		out[domain] = string(b)
	}
	if eio.Out != nil {
		fmt.Fprintf(eio.Out, "✓ Session stored for %s\n", strings.Join(workspaces, ", "))
	}
	return out, nil
}

var (
	// d=xoxd-… in a Cookie header, a -b argument or a $session cookie line.
	slackDCookieRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])d=(xoxd-[^;\s"'\\]+)`)
	// PowerShell's Copy as PowerShell: New-Object System.Net.Cookie("d", "xoxd-…", …).
	slackPSCookieRE = regexp.MustCompile(`Cookie\(\s*"d"\s*,\s*"(xoxd-[^"]+)"`)
	// A bare xoxd-… value on its own line.
	slackBareCookieRE = regexp.MustCompile(`(?m)^[ \t]*(xoxd-[^;\s"'\\]+);?[ \t]*\r?$`)
)

// parseSlackCookie finds the d cookie in a pasted browser request (cURL bash,
// cmd or PowerShell form), a d=… pair, or a bare value, and returns it
// URL-encoded, the form Slack sends. "" means none was found. It accepts the
// same forms as slk's --add-workspace --browser, which it mirrors without
// importing.
func parseSlackCookie(paste string) string {
	// cmd's Copy as cURL escapes with carets (^", ^%), none of which can be
	// part of a cookie.
	if strings.Contains(paste, `^"`) {
		paste = strings.ReplaceAll(paste, "^", "")
	}
	var cookie string
	for _, re := range []*regexp.Regexp{slackDCookieRE, slackPSCookieRE, slackBareCookieRE} {
		if m := re.FindStringSubmatch(paste); m != nil {
			cookie = m[1]
			break
		}
	}
	// DevTools' Application tab can show the value decoded
	// (xoxd-AbC/def+Ghi==); an encoded one has none of /+=.
	if strings.ContainsAny(cookie, "/+=") {
		cookie = url.QueryEscape(cookie)
	}
	return cookie
}

// stringifyField renders an existing KVv2 value as the string the engine
// contract carries: strings verbatim, anything else as JSON so it is kept
// rather than dropped. Shared by the copy and slack engines' merges.
func stringifyField(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
