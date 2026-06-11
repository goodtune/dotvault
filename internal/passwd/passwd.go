// Package passwd answers one narrow question for `dotvault login-check
// --no-passwd`: does the current OS user have an entry in the local
// passwd file? In corporate fleets where human accounts come from a
// directory service (SSSD, LDAP, AD), an account listed in /etc/passwd
// is a local machine account — not a human with Vault credentials — so
// login-check can exit before any token checks or prompts.
//
// The file is parsed directly rather than via getent/os/user lookups,
// which merge every NSS source and cannot say *which* source an entry
// came from — exactly the distinction this check exists to draw.
// Deliberately no third-party dependency: the format is a stable,
// trivially line-oriented contract (passwd(5)) and the libraries that
// exist parse far more than the lookup needs.
//
// The heuristic is Linux-targeted. On macOS local accounts live in
// Open Directory, not /etc/passwd (which holds only system and
// single-user-mode entries), so the lookup never matches a human there
// and --no-passwd degrades safely to a no-op: the caller falls through
// to the normal login check rather than skipping it.
package passwd

import (
	"bufio"
	"io"
	"os"
	"strings"
)

const (
	// DefaultPath is the local account database on Linux. On macOS the
	// file holds only system and single-user-mode entries (see the
	// package doc), so the lookup never matches a human account there.
	// The Windows caller never reaches this package (the flag is
	// ignored there).
	DefaultPath = "/etc/passwd"

	envPath = "DOTVAULT_PASSWD_FILE"
)

// Path returns the passwd file to consult: the DOTVAULT_PASSWD_FILE
// override when set (used primarily by tests, mirroring
// DOTVAULT_SUPPRESS_MARKER), otherwise DefaultPath.
func Path() string {
	if p := os.Getenv(envPath); p != "" {
		return p
	}
	return DefaultPath
}

// ContainsUser reports whether the passwd file at path defines a local
// entry for username. A missing or unreadable file is an error — the
// caller decides whether to fail open; this package does not guess.
func ContainsUser(path, username string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	return scan(f, username)
}

// scan is the io.Reader core of ContainsUser, split out for tests.
// Matching is exact on the first colon-separated field of each entry,
// per passwd(5). Lines that are not local entries are skipped:
//   - blank lines and #-comments (not standard, but present on some
//     systems and emitted by some provisioning tools)
//   - NIS/compat `+`/`-` entries (`+@netgroup`, `+username`, bare `+`),
//     which splice in *directory* sources — the opposite of the "local
//     account" signal this lookup exists to detect
//   - lines without a colon (malformed; no name field to match)
func scan(r io.Reader, username string) (bool, error) {
	if username == "" {
		return false, nil
	}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			continue
		}
		name, _, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		if name == username {
			return true, nil
		}
	}
	return false, sc.Err()
}
