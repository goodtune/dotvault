package agent

import (
	"context"
	"fmt"
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
		case "agent":
			sources = append(sources, newUpstreamSourceFromConfig(i, k, username, uid, self))
		default:
			sources = append(sources, newErrSource(fmt.Sprintf("keys[%d]", i), k.Source, fmt.Errorf("unknown source %q", k.Source)))
		}
	}
	return sources, nil
}

// newUpstreamSourceFromConfig builds an `agent` source in one of two modes.
//
// With no socket/pipe configured it auto-detects: the source re-scans the
// platform's well-known agent locations on every listing and proxies to
// whatever this user is actually running. That is the mode the feature exists
// for — a client pointed at dotvault's endpoint once, permanently, finds the
// user's other agents without anyone having written their paths down, and
// keeps finding them when a keyring daemon or a forwarded socket comes and
// goes mid-session.
//
// With an explicit socket/pipe it proxies to exactly that endpoint (still
// expanding {{.username}}/{{.uid}}), which is the escape hatch for an agent at
// a path discovery does not know. A resolution problem there becomes an
// errSource so it surfaces in status without aborting the daemon — the other
// sources stay live.
//
// Both modes are guarded against pointing back at any endpoint this daemon
// serves the agent on, which would loop List/Sign into itself forever. The
// explicit mode compares paths here; the auto mode hands the same endpoint
// list to discovery, which additionally asks each candidate over the wire
// whether it is us (see IDExtension) — necessary because SSH_AUTH_SOCK
// commonly *is* dotvault by then, reachable by a path that never string-equals
// the one we bound.
func newUpstreamSourceFromConfig(i int, k config.AgentKeySource, username, uid string, selfEndpoints []string) Source {
	const name = "agent"
	if !upstreamEndpointConfigured(k) {
		return newAutoUpstreamSource(name+":auto", selfEndpoints)
	}
	endpoint, err := resolveUpstreamEndpoint(k, username, uid)
	if err != nil {
		return newErrSource(name, "agent", fmt.Errorf("agent.keys[%d]: %w", i, err))
	}
	norm := normalizeEndpoint(endpoint)
	for _, self := range selfEndpoints {
		if normalizeEndpoint(self) == norm {
			return newErrSource(name, "agent", fmt.Errorf("agent.keys[%d]: upstream endpoint %q is dotvault's own agent endpoint (would loop)", i, endpoint))
		}
	}
	return newUpstreamSource(name+":"+endpoint, endpoint)
}

// upstreamEndpointConfigured reports whether the operator named an explicit
// endpoint for this platform. Only the field this platform uses counts: a
// config carrying both `socket` and `pipe` (the portable case — one YAML
// deployed to a mixed fleet) must auto-detect on neither, and a config
// carrying only the other platform's field must auto-detect on this one.
func upstreamEndpointConfigured(k config.AgentKeySource) bool {
	if runtime.GOOS == "windows" {
		return strings.TrimSpace(k.Pipe) != ""
	}
	return strings.TrimSpace(k.Socket) != ""
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

// resolveUpstreamEndpoint expands an explicitly configured `agent` endpoint:
// {{.username}} / {{.uid}} templating, plus ~ expansion for a Unix socket
// path. It is only reached when the operator named one — an unset socket/pipe
// auto-detects instead of falling back to a platform default, which is what
// retired the old "$XDG_RUNTIME_DIR is unset on macOS, so configure it
// yourself" dead end.
func resolveUpstreamEndpoint(k config.AgentKeySource, username, uid string) (string, error) {
	raw := k.Socket
	if runtime.GOOS == "windows" {
		raw = k.Pipe
	}
	endpoint, err := renderEndpointTemplate(raw, username, uid)
	if err != nil {
		return "", err
	}
	// Reject an endpoint that rendered empty (e.g. a socket set to a bare
	// "{{.uid}}" when the UID lookup failed) rather than letting it become an
	// empty dial target with a confusing downstream error.
	if strings.TrimSpace(endpoint) == "" {
		return "", fmt.Errorf("upstream agent endpoint resolved to empty; check the socket/pipe value and its {{.username}}/{{.uid}} template")
	}
	if runtime.GOOS != "windows" {
		if expanded, err := paths.ExpandHome(endpoint); err != nil {
			return "", fmt.Errorf("expand upstream agent socket %q: %w", endpoint, err)
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
