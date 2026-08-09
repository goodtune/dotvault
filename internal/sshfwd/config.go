// Package sshfwd implements dotvault's daemon-managed SSH remote forwards: a
// declarative reconciler that keeps an SSH connection to each configured host
// and exposes dotvault's own web API there as a Unix socket, replacing the
// external `ssh -R` that vault.token_socket has depended on.
package sshfwd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultRemoteSocket is the socket path used when a remote does not name one.
// The leading ~ is expanded against the *remote* account's home at connect
// time, not here — see home.go.
const DefaultRemoteSocket = "~/.ssh/dotvault.sock"

// DefaultPort is the SSH port used when a remote does not name one.
const DefaultPort = 22

// Remote is one configured SSH host whose forward the daemon maintains.
//
// Host is the entry's identity: `ssh add` is idempotent on it and `ssh remove`
// keys on it.
type Remote struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port,omitempty"`

	// RemoteSocket is the Unix socket path bound on the remote. Absolute, or
	// prefixed "~/" for the remote account's home. Storing ~ rather than a
	// resolved path keeps the entry portable if the remote home moves.
	RemoteSocket string `yaml:"remote_socket"`

	// HostKey pins the remote's host key in authorized_keys form. Empty when a
	// configured certificate authority covers the host instead.
	HostKey string `yaml:"host_key,omitempty"`

	// Enabled is a pointer so an explicit `enabled: false` is distinguishable
	// from an unset field (which defaults to true) and survives a round trip.
	Enabled *bool `yaml:"enabled,omitempty"`
}

// EnabledOrDefault reports whether the daemon should manage this remote. An
// unset value defaults to true.
func (r Remote) EnabledOrDefault() bool { return r.Enabled == nil || *r.Enabled }

// PortOrDefault returns the SSH port, defaulting to 22.
func (r Remote) PortOrDefault() int {
	if r.Port == 0 {
		return DefaultPort
	}
	return r.Port
}

// sameAs reports whether r and o describe the same managed connection, for
// deciding whether Manager.Reconcile can leave a running remote untouched.
//
// This must not be struct equality (==): Enabled is a *bool, and Load
// re-decodes YAML fresh on every call, producing a new pointer for the same
// boolean value each time it's invoked. A pointer-address comparison would
// read an unchanged, explicitly `enabled: true` remote as "changed" on every
// single reconcile pass — tearing down and re-dialling a live connection,
// its bound remote socket, and every in-flight relay through it, forever.
// Comparing EnabledOrDefault() instead compares the resolved boolean, not
// the pointer, and folds "explicitly true" and "unset" into one state as
// they already are everywhere else. Host is compared case-insensitively to
// match File.Find's identity rule.
func (r Remote) sameAs(o Remote) bool {
	return strings.EqualFold(r.Host, o.Host) &&
		r.Port == o.Port &&
		r.RemoteSocket == o.RemoteSocket &&
		r.HostKey == o.HostKey &&
		r.EnabledOrDefault() == o.EnabledOrDefault()
}

// File is the parsed ssh.yaml document.
//
// unknown retains any top-level key this build does not recognise so a rewrite
// by an older binary cannot silently drop a section a newer one wrote.
type File struct {
	Remotes []Remote `yaml:"remotes"`

	unknown map[string]*yaml.Node
}

// Find returns the index of the remote with the given host.
func (f *File) Find(host string) (int, bool) {
	for i, r := range f.Remotes {
		if strings.EqualFold(r.Host, host) {
			return i, true
		}
	}
	return -1, false
}

// Upsert replaces the entry for r.Host, or appends it when absent.
func (f *File) Upsert(r Remote) {
	if i, ok := f.Find(r.Host); ok {
		f.Remotes[i] = r
		return
	}
	f.Remotes = append(f.Remotes, r)
}

// Remove deletes the entry for host, reporting whether one was present.
func (f *File) Remove(host string) bool {
	i, ok := f.Find(host)
	if !ok {
		return false
	}
	f.Remotes = append(f.Remotes[:i], f.Remotes[i+1:]...)
	return true
}

// Load reads ssh.yaml. A missing file is an empty document, not an error: a
// user who has never run `dotvault ssh add` has no file and no remotes, which
// is a valid state rather than a misconfiguration.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &File{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var raw map[string]yaml.Node
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	f := &File{unknown: map[string]*yaml.Node{}}
	for k, v := range raw {
		if k == "remotes" {
			if err := v.Decode(&f.Remotes); err != nil {
				return nil, fmt.Errorf("parse %s: remotes: %w", path, err)
			}
			continue
		}
		f.unknown[k] = &v
	}
	return f, nil
}

// Save writes ssh.yaml atomically at 0600 inside a 0700 directory. The file
// records which hosts this user connects to and pins their keys.
func Save(path string, f *File) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	out := map[string]any{"remotes": f.Remotes}
	for k, v := range f.unknown {
		out[k] = v
	}
	data, err := yaml.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal ssh config: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".ssh.yaml.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// ValidateRemoteSocket enforces the socket-path rules. Only an absolute path
// or a "~/"-prefixed one is accepted: "~user/" would require resolving another
// account's home on the remote, which dotvault cannot do, and silently
// mishandling it would bind somewhere the user did not intend. Paths containing
// .. segments are rejected to prevent escape to parent directories.
func ValidateRemoteSocket(p string) error {
	switch {
	case p == "":
		return errors.New("remote_socket must not be empty")
	case strings.ContainsRune(p, 0):
		return errors.New("remote_socket must not contain a NUL byte")
	case strings.HasPrefix(p, "~/"):
		// Check for .. segments that could escape the home directory.
		rest := strings.TrimPrefix(p, "~/")
		for _, segment := range strings.Split(rest, "/") {
			if segment == ".." {
				return errors.New("remote_socket must not contain .. path segments")
			}
		}
		return nil
	case strings.HasPrefix(p, "~"):
		return errors.New(`~user/ is not supported; use an absolute path or ~/`)
	case strings.HasPrefix(p, "/"):
		// Absolute paths also need .. checking to be safe.
		for _, segment := range strings.Split(p, "/") {
			if segment == ".." {
				return errors.New("remote_socket must not contain .. path segments")
			}
		}
		return nil
	default:
		return errors.New(`must be absolute or start with ~/`)
	}
}

// ValidateRemote checks a single entry. The host validation guards against
// injection attacks: ssh(1) will be invoked with this host string as a load-bearing
// argument, so a leading dash or embedded @ must be rejected to prevent option-injection
// or user-field manipulation.
func ValidateRemote(r Remote) error {
	if r.Host == "" {
		return errors.New("host is required")
	}
	// Embedded @ is a user-field injection vector: "user@host" is the SSH login syntax,
	// and the user comes from dotvault's agent identity, not this field.
	// Leading dash is an option-injection vector: ssh treats "-oProxyCommand=..." as an option.
	if strings.HasPrefix(r.Host, "-") {
		return fmt.Errorf("invalid host %q: must not start with -", r.Host)
	}
	// Embedded @ is a user-field injection vector: "user@host" is the SSH login syntax,
	// and the user comes from dotvault's agent identity, not this field.
	if strings.ContainsRune(r.Host, '@') {
		return fmt.Errorf("invalid host %q: must not contain @", r.Host)
	}
	// Reject control characters (< 0x20 and DEL 0x7f) that have no place in a hostname.
	for _, b := range r.Host {
		if b < 0x20 || b == 0x7f {
			return fmt.Errorf("invalid host %q: must not contain control characters", r.Host)
		}
	}
	// Reject other problematic characters that could confuse shell parsing or path handling.
	if strings.ContainsAny(r.Host, " \t\r\n/\\") {
		return fmt.Errorf("invalid host %q", r.Host)
	}
	if r.Port < 0 || r.Port > 65535 {
		return fmt.Errorf("port %d out of range 1-65535", r.Port)
	}
	return ValidateRemoteSocket(r.RemoteSocket)
}
