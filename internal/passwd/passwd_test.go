package passwd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sample mirrors a realistic compat-mode /etc/passwd: system accounts,
// a local human-shaped account, comments, NIS splice entries, and a
// malformed line. The directory-sourced user "gary" is deliberately
// absent — that is the whole point of the lookup.
const sample = `# local accounts
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

svc-backup:x:998:998:gary backup service:/var/lib/backup:/usr/sbin/nologin
+@humans
+gary
-blocked
+::::::
not-an-entry-without-colon
localadmin:x:1000:1000::/home/localadmin:/bin/bash
`

func TestScan(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     bool
	}{
		{"local system account", "root", true},
		{"local trailing entry", "localadmin", true},
		{"local service account", "svc-backup", true},
		{"directory user absent from file", "gary", false},
		{"nis netgroup splice not a local entry", "@humans", false},
		{"prefix of a local name", "local", false},
		{"local name plus suffix", "rootx", false},
		{"match in gecos field only", "backup", false},
		{"comment line", "# local accounts", false},
		{"empty username", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scan(strings.NewReader(sample), tt.username)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if got != tt.want {
				t.Errorf("scan(%q) = %v, want %v", tt.username, got, tt.want)
			}
		})
	}
}

func TestScanCRLF(t *testing.T) {
	got, err := scan(strings.NewReader("alice:x:1:1::/home/alice:/bin/sh\r\n"), "alice")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !got {
		t.Error("CRLF line ending should not defeat the username match")
	}
}

func TestContainsUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}
	found, err := ContainsUser(path, "localadmin")
	if err != nil {
		t.Fatalf("ContainsUser: %v", err)
	}
	if !found {
		t.Error("ContainsUser(localadmin) = false, want true")
	}
	found, err = ContainsUser(path, "gary")
	if err != nil {
		t.Fatalf("ContainsUser: %v", err)
	}
	if found {
		t.Error("ContainsUser(gary) = true, want false")
	}
}

// A missing file must surface as an error, not a silent "not found" —
// the caller's fail-open decision should be deliberate and logged.
func TestContainsUserMissingFile(t *testing.T) {
	_, err := ContainsUser(filepath.Join(t.TempDir(), "nope"), "root")
	if err == nil {
		t.Fatal("ContainsUser on missing file: want error, got nil")
	}
}

func TestPathOverride(t *testing.T) {
	t.Setenv(envPath, "/tmp/custom-passwd")
	if got := Path(); got != "/tmp/custom-passwd" {
		t.Errorf("Path() with override = %q", got)
	}
	t.Setenv(envPath, "")
	if got := Path(); got != DefaultPath {
		t.Errorf("Path() without override = %q, want %q", got, DefaultPath)
	}
}
