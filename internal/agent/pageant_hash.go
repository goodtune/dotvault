package agent

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// pageantSuffixHash lives in this build-tag-free file (rather than the
// Windows-only listener_windows.go) so the wire-encoding step can be unit
// tested on any OS without the Windows-only CryptProtectMemory call; only the
// Windows build actually calls it.
//
// pageantSuffixHash reproduces the final hashing step of PuTTY's
// capi_obfuscate_string (windows/utils/cryptoapi.c). The
// CryptProtectMemory-obfuscated buffer is fed to SHA-256 through PuTTY's
// BinarySink put_string, which prefixes the data with its length as a
// big-endian uint32 — the SSH wire-string encoding — before the bytes
// themselves. The lower-case hex digest is the suffix of the
// \\.\pipe\pageant.<user>.<hash> name PuTTY-family clients dial.
//
// This length prefix is load-bearing: PuTTY's pre-CMake-refactor code
// (windows/wincapi.c) hashed the raw obfuscated bytes with no prefix, and a
// clone that hashes the raw bytes (as this code originally did) derives the
// stale pre-refactor name — a real, current PuTTY computes the prefixed name
// and never looks at the pipe dotvault would serve. The prefix is the only
// difference between the two forms; everything feeding the obfuscation (the
// "Pageant" class string, the 16-byte block padding, the CROSS_PROCESS flag)
// is identical, so on a given machine the obfuscated bytes match and only the
// hashing diverges.
func pageantSuffixHash(obfuscated []byte) string {
	buf := make([]byte, 4+len(obfuscated))
	binary.BigEndian.PutUint32(buf, uint32(len(obfuscated)))
	copy(buf[4:], obfuscated)
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}
