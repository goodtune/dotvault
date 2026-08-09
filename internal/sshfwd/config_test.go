package sshfwd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRemoteSocket(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{"tilde home", "~/.ssh/dotvault.sock", ""},
		{"absolute", "/run/user/1000/dotvault.sock", ""},
		{"empty", "", "must not be empty"},
		{"tilde user", "~other/.ssh/dotvault.sock", "~user/ is not supported"},
		{"bare tilde", "~", "~user/ is not supported"},
		{"relative", ".ssh/dotvault.sock", "must be absolute or start with ~/"},
		{"nul byte", "/tmp/a\x00b", "must not contain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRemoteSocket(tt.path)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateRemoteSocket(%q) = %v, want nil", tt.path, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateRemoteSocket(%q) = %v, want error containing %q", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRemote(t *testing.T) {
	tests := []struct {
		name    string
		remote  Remote
		wantErr string
	}{
		{"minimal", Remote{Host: "foo.example.com", RemoteSocket: "~/.ssh/dotvault.sock"}, ""},
		{"no host", Remote{RemoteSocket: "~/.ssh/dotvault.sock"}, "host is required"},
		{"host with space", Remote{Host: "foo bar", RemoteSocket: "~/x.sock"}, "invalid host"},
		{"leading dash option", Remote{Host: "-oProxyCommand=id", RemoteSocket: "~/x.sock"}, "must not start with -"},
		{"leading dash short opt", Remote{Host: "-4", RemoteSocket: "~/x.sock"}, "must not start with -"},
		{"embedded at sign", Remote{Host: "root@evil.example.com", RemoteSocket: "~/x.sock"}, "must not contain @"},
		{"control character", Remote{Host: "foo\x00bar.example.com", RemoteSocket: "~/x.sock"}, "control characters"},
		{"port low", Remote{Host: "a.example.com", Port: -1, RemoteSocket: "~/x.sock"}, "port"},
		{"port high", Remote{Host: "a.example.com", Port: 70000, RemoteSocket: "~/x.sock"}, "port"},
		{"bad socket", Remote{Host: "a.example.com", RemoteSocket: "rel/x.sock"}, "must be absolute"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRemote(tt.remote)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateRemote() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateRemote() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	f, err := Load(filepath.Join(t.TempDir(), "ssh.yaml"))
	if err != nil {
		t.Fatalf("Load() on missing file = %v, want nil", err)
	}
	if len(f.Remotes) != 0 {
		t.Fatalf("Load() on missing file returned %d remotes, want 0", len(f.Remotes))
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh.yaml")
	enabled := false
	in := &File{Remotes: []Remote{
		{Host: "foo.example.com", Port: 2222, RemoteSocket: "~/.ssh/dotvault.sock", HostKey: "ssh-ed25519 AAAAC3Nz", Enabled: &enabled},
		{Host: "bar.example.com", RemoteSocket: "/run/dotvault.sock"},
	}}
	if err := Save(path, in); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if len(out.Remotes) != 2 {
		t.Fatalf("Load() returned %d remotes, want 2", len(out.Remotes))
	}
	if out.Remotes[0].Port != 2222 || out.Remotes[0].HostKey != "ssh-ed25519 AAAAC3Nz" {
		t.Errorf("remote[0] = %+v, lost fields on round trip", out.Remotes[0])
	}
	if out.Remotes[0].EnabledOrDefault() {
		t.Error("remote[0].EnabledOrDefault() = true, want false (explicit enabled: false must survive)")
	}
	if !out.Remotes[1].EnabledOrDefault() {
		t.Error("remote[1].EnabledOrDefault() = false, want true (unset defaults to enabled)")
	}
	if got := out.Remotes[1].PortOrDefault(); got != 22 {
		t.Errorf("remote[1].PortOrDefault() = %d, want 22", got)
	}
}

func TestSavePreservesUnknownKeys(t *testing.T) {
	// An older build must not silently drop a section a newer build wrote.
	path := filepath.Join(t.TempDir(), "ssh.yaml")
	raw := "remotes:\n  - host: foo.example.com\n    remote_socket: ~/.ssh/dotvault.sock\nfuture_section:\n  keep: me\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	f.Upsert(Remote{Host: "bar.example.com", RemoteSocket: "~/.ssh/dotvault.sock"})
	if err := Save(path, f); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "future_section") || !strings.Contains(string(data), "keep: me") {
		t.Errorf("Save() dropped unknown keys:\n%s", data)
	}
}

func TestSaveIsAtomicAnd0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssh.yaml")
	if err := Save(path, &File{Remotes: []Remote{{Host: "a.example.com", RemoteSocket: "~/x.sock"}}}); err != nil {
		t.Fatalf("Save() = %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeIsUnix() && fi.Mode().Perm() != 0600 {
		t.Errorf("Save() mode = %o, want 0600", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("Save() left %d entries, want 1 (no temp file)", len(entries))
	}
}

func TestUpsertIsIdempotentOnHost(t *testing.T) {
	f := &File{}
	f.Upsert(Remote{Host: "foo.example.com", RemoteSocket: "~/a.sock"})
	f.Upsert(Remote{Host: "foo.example.com", RemoteSocket: "~/b.sock"})
	if len(f.Remotes) != 1 {
		t.Fatalf("Upsert() twice produced %d remotes, want 1", len(f.Remotes))
	}
	if f.Remotes[0].RemoteSocket != "~/b.sock" {
		t.Errorf("Upsert() did not replace: %+v", f.Remotes[0])
	}
}

func TestRemove(t *testing.T) {
	f := &File{Remotes: []Remote{{Host: "a.example.com"}, {Host: "b.example.com"}}}
	if !f.Remove("a.example.com") {
		t.Error("Remove() = false, want true")
	}
	if f.Remove("missing.example.com") {
		t.Error("Remove() on absent host = true, want false")
	}
	if len(f.Remotes) != 1 || f.Remotes[0].Host != "b.example.com" {
		t.Errorf("Remove() left %+v", f.Remotes)
	}
}

func runtimeIsUnix() bool { return os.PathSeparator == '/' }
