package agent

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/paths"
	"github.com/goodtune/dotvault/internal/vault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// defaultWindowsUpstreamPipe is the named pipe served by the built-in Windows
// OpenSSH agent service — the first place upstream auto-detection looks.
const defaultWindowsUpstreamPipe = `\\.\pipe\openssh-ssh-agent`

// errSource is a placeholder for a key source that could not be constructed
// (unknown engine, unsupported option). It owns no keys and reports its reason
// via Identities, so the failure shows up in agent status without aborting the
// daemon — mirroring the enrolment picker's "error: …" rows.
type errSource struct {
	name string
	typ  string
	err  error
}

func newErrSource(name, typ string, err error) Source {
	return &errSource{name: name, typ: typ, err: err}
}

func (s *errSource) Name() string                                   { return s.name }
func (s *errSource) Type() string                                   { return s.typ }
func (s *errSource) Identities(context.Context) ([]Identity, error) { return nil, s.err }
func (s *errSource) Sign(context.Context, ssh.PublicKey, []byte, agent.SignatureFlags) (*ssh.Signature, bool, error) {
	return nil, false, nil
}

// NewSourcesFromConfig builds the ordered key sources for the daemon from the
// agent config. kvMount/userPrefix/username come from the running config and
// identity resolution (userPrefix carries its trailing slash).
func NewSourcesFromConfig(agentCfg config.AgentConfig, vc *vault.Client, kvMount, userPrefix, username string) ([]Source, error) {
	base := userPrefix + username + "/"
	// self is the full set of endpoints this daemon serves the agent on — the
	// primary plus, on Windows with PuTTY enabled, the Pageant-convention pipe.
	// An upstream source pointed at any of them would loop List/Sign back into
	// this daemon forever, so the guard below checks membership against all of
	// them, not just the primary.
	self := resolveServeEndpoints(agentCfg, ResolveEndpoint(agentCfg))
	uid, _ := paths.UID() // best-effort; an empty uid just renders {{.uid}} blank
	sources := make([]Source, 0, len(agentCfg.Keys))
	for i, k := range agentCfg.Keys {
		switch k.Source {
		case "kv":
			p, name := kvPrefixAndName(k.PathPrefix)
			sources = append(sources, newKVSource(name, vc, kvMount, base+p))
		case "vault-ca":
			ttl, err := parseTTL(k.TTL)
			if err != nil {
				return nil, fmt.Errorf("agent.keys[%d].ttl: %w", i, err)
			}
			name := "vault-ca:" + k.Role
			src, err := newVaultCASource(name, vaultCertSigner{client: vc}, k.Mount, k.Role, k.Principals, username, ttl, k.EphemeralKey)
			if err != nil {
				return nil, fmt.Errorf("agent.keys[%d]: %w", i, err)
			}
			sources = append(sources, src)
		default:
			sources = append(sources, newErrSource(fmt.Sprintf("keys[%d]", i), k.Source, fmt.Errorf("unknown source %q", k.Source)))
		}
	}
	// The relay goes last, always, and is not one of the keys[] entries. Last
	// because dotvault's own identities should be offered first — an ssh client
	// works down the list against the server's MaxAuthTries budget, so the keys
	// this daemon is responsible for get the first attempts and the shadowed
	// agents fill in behind them. Appended here rather than configured because
	// it is on by default; see config.AgentRelayConfig.Enabled.
	if agentCfg.RelayEnabled() {
		sources = append(sources, newRelaySource(agentCfg, username, uid, self))
	}
	return sources, nil
}

// newRelaySource builds the implicit upstream-agent relay in one of two modes.
//
// With no relay.socket/relay.pipe configured it auto-detects: it re-scans the
// platform's well-known agent locations on every listing and proxies to
// whatever this user is actually running. That is the mode the feature exists
// for — a client pointed at dotvault's endpoint once, permanently, finds the
// user's other agents without anyone having written their paths down, and
// keeps finding them when a keyring daemon or a forwarded socket comes and
// goes mid-session.
//
// With an explicit endpoint it proxies to exactly that one (still expanding
// {{.username}}/{{.uid}}). That is the escape hatch for an agent at a path
// detection does not know. It is not a security control and must not be sold
// as one: pinning names which endpoint is dialled, never who answers, and on
// Unix it actively gives up the peer-ownership check auto-detection performs —
// hence the warning. A resolution problem becomes an errSource so it surfaces
// in status without aborting the daemon; the configured key sources stay live.
//
// Both modes are guarded against pointing back at an endpoint this daemon
// serves, which would loop List/Sign into itself forever. The explicit mode
// compares paths here; the auto mode hands the same endpoint list to
// discovery, which additionally asks each candidate over the wire whether it
// is us (see IDExtension) — necessary because SSH_AUTH_SOCK commonly *is*
// dotvault by then, reachable by a path that never string-equals the one we
// bound.
func newRelaySource(agentCfg config.AgentConfig, username, uid string, selfEndpoints []string) Source {
	const name = "relay"
	if !relayEndpointConfigured(agentCfg) {
		warnRelayDetectionTrust()
		return newAutoUpstreamSource(name+":auto", selfEndpoints)
	}
	endpoint, err := resolveRelayEndpoint(agentCfg, username, uid)
	if err != nil {
		return newErrSource(name, "agent", err)
	}
	norm := normalizeEndpoint(endpoint)
	for _, self := range selfEndpoints {
		if normalizeEndpoint(self) == norm {
			return newErrSource(name, "agent", fmt.Errorf("agent.relay.socket/relay.pipe %q is dotvault's own agent endpoint (would loop)", endpoint))
		}
	}
	// Say out loud what pinning costs. Auto-detection asks the kernel who is
	// on the other end of each connection and drops anything not owned by this
	// uid (peerUID, upstreamSource.connect); a named endpoint deliberately
	// skips that, because the operator may well mean an agent running as
	// another account. That is a legitimate choice and a quiet one, and
	// `ssh-add` through dotvault forwards a private key to whatever answers
	// here — so it is stated at startup rather than left in the docs.
	slog.Warn("ssh agent: relay pinned to a configured endpoint; the peer-ownership check auto-detection performs is skipped for it",
		"endpoint", endpoint)
	return newUpstreamSource(name+":"+endpoint, endpoint)
}

// warnRelayDetectionTrust says, once per daemon, what auto-detection can and
// cannot verify on this platform.
//
// It is a no-op where peer credentials are available (Linux, macOS): there the
// kernel answers "is this endpoint mine" on the connection itself and there is
// nothing to caveat. Everywhere else — Windows above all, where peerUID has no
// implementation at all — detection rests on the endpoint's *name*, and the
// two well-known Windows agent pipes are not tamper-proof names: the namespace
// is first-creator-wins, and the Pageant name's per-boot hash comes from
// CryptProtectMemory(CROSS_PROCESS), which any process on the machine can
// reverse.
//
// The relay is on by default, and forwarding a client's `ssh-add` to a squatted
// pipe deposits a private key there. That exposure is the one ssh.exe and every
// PuTTY client already carry when they dial these same names, so dotvault is
// inheriting it rather than widening it — but it is now inherited by default
// instead of on request, which is precisely why it gets said rather than
// documented. relay.enabled: false is the control.
func warnRelayDetectionTrust() {
	if peerCredentialsAvailable {
		return
	}
	slog.Warn("ssh agent: relaying to auto-detected agents on a platform with no peer-credential check; endpoints are trusted by name, which is not tamper-proof (set agent.relay.enabled: false to turn the relay off)",
		"os", runtime.GOOS)
}

// relayEndpointConfigured reports whether the operator pinned the relay to an
// explicit endpoint for this platform. Only the field this platform uses
// counts: a config carrying both relay.socket and relay.pipe (the portable
// case — one YAML deployed to a mixed fleet) must auto-detect on neither, and
// a config carrying only the other platform's field must auto-detect on this
// one.
func relayEndpointConfigured(a config.AgentConfig) bool {
	if runtime.GOOS == "windows" {
		return strings.TrimSpace(a.Relay.Pipe) != ""
	}
	return strings.TrimSpace(a.Relay.Socket) != ""
}

// normalizeEndpoint canonicalises an endpoint for the self-reference
// comparison: a Unix socket path is path-cleaned (so `..`, `.`, and redundant
// slashes don't slip the guard); a Windows pipe name is lower-cased (the pipe
// namespace is case-insensitive). Symlinks are deliberately not resolved — the
// socket may not exist yet at construction time, and the comparison is a
// best-effort loop guard, not a security boundary (the upstream is the same OS
// user as the daemon).
func normalizeEndpoint(s string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(s)
	}
	return filepath.Clean(s)
}

// resolveRelayEndpoint expands an explicitly pinned relay endpoint:
// {{.username}} / {{.uid}} templating, plus ~ expansion for a Unix socket
// path. It is only reached when the operator named one — an unset
// relay.socket/relay.pipe auto-detects instead of falling back to a platform
// default, which is what retired the old "$XDG_RUNTIME_DIR is unset on macOS,
// so configure it yourself" dead end.
func resolveRelayEndpoint(a config.AgentConfig, username, uid string) (string, error) {
	raw := a.Relay.Socket
	if runtime.GOOS == "windows" {
		raw = a.Relay.Pipe
	}
	endpoint, err := renderEndpointTemplate(raw, username, uid)
	if err != nil {
		return "", err
	}
	// Reject an endpoint that rendered empty (e.g. a socket set to a bare
	// "{{.uid}}" when the UID lookup failed) rather than letting it become an
	// empty dial target with a confusing downstream error.
	if strings.TrimSpace(endpoint) == "" {
		return "", fmt.Errorf("agent.relay.socket/relay.pipe resolved to empty; check the value and its {{.username}}/{{.uid}} template")
	}
	if runtime.GOOS != "windows" {
		if expanded, err := paths.ExpandHome(endpoint); err != nil {
			return "", fmt.Errorf("expand agent.relay.socket %q: %w", endpoint, err)
		} else {
			endpoint = expanded
		}
	}
	return endpoint, nil
}

// renderEndpointTemplate expands {{.username}} and {{.uid}} in an agent
// endpoint. A template with no actions passes through unchanged. Both inputs
// are OS-derived (paths.Username/paths.UID — the account dotvault runs as), not
// attacker-controlled, and the rendered result is a socket/pipe the same user
// already controls, so there is no injection surface to sanitise.
//
// missingkey=error makes a mis-typed variable (e.g. {{.user}}) fail here, at
// source construction, with a clear message — rather than rendering "<no value>"
// into the path and surfacing later as a confusing dial error. An empty but
// present key ({{.uid}} when the UID lookup failed) still renders "" without
// error; only an absent key is rejected.
func renderEndpointTemplate(raw, username, uid string) (string, error) {
	t, err := template.New("agent-endpoint").Option("missingkey=error").Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse endpoint template %q: %w", raw, err)
	}
	var b strings.Builder
	if err := t.Execute(&b, map[string]string{"username": username, "uid": uid}); err != nil {
		return "", fmt.Errorf("expand endpoint template %q: %w", raw, err)
	}
	return b.String(), nil
}

func parseTTL(s string) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	return config.ParseDuration(s)
}

// kvPrefixAndName normalises a KV source's configured path_prefix (strip a
// leading slash, ensure exactly one trailing slash) and derives the source's
// display name.
func kvPrefixAndName(pathPrefix string) (prefix, name string) {
	p := strings.TrimPrefix(pathPrefix, "/")
	if p != "" && !strings.HasSuffix(p, "/") {
		p += "/"
	}
	name = "kv"
	if p != "" {
		name = "kv:" + strings.TrimSuffix(p, "/")
	}
	return p, name
}
