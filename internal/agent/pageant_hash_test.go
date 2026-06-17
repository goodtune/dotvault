package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestPageantSuffixHashLengthPrefixed pins the Pageant suffix hashing to
// PuTTY's current put_string encoding: a four-byte big-endian length followed
// by the obfuscated bytes, then SHA-256. The vector is a fixed 16-byte buffer
// (0x00..0x0f) standing in for the CryptProtectMemory output, so the test runs
// on every platform without touching the Windows crypto API.
func TestPageantSuffixHashLengthPrefixed(t *testing.T) {
	obfuscated := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	const wantPrefixed = "c439a3843ed50b618469844284e929fc9de79c221380274aa313b841feb1b8b1"
	if got := pageantSuffixHash(obfuscated); got != wantPrefixed {
		t.Errorf("pageantSuffixHash = %q, want %q (4-byte BE length prefix + data)", got, wantPrefixed)
	}

	// Guard against a regression to the pre-CMake-refactor PuTTY form, which
	// hashed the raw obfuscated bytes with no length prefix. That form derives
	// a stale pipe name no current PuTTY client dials.
	rawSum := sha256.Sum256(obfuscated)
	if got := pageantSuffixHash(obfuscated); got == hex.EncodeToString(rawSum[:]) {
		t.Errorf("pageantSuffixHash hashed raw bytes; the put_string length prefix is missing")
	}
}
