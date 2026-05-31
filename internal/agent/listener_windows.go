//go:build windows

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/goodtune/dotvault/internal/paths"
)

// dialEndpoint connects to an existing agent named pipe as a client. It never
// creates the pipe — `dotvault status` must observe the running daemon, not
// stand up a competing listener.
func dialEndpoint(ctx context.Context, addr string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, addr)
}

// agentPipeSDDL is the security descriptor applied to the named pipe. Windows
// has no per-user protected subspace in the pipe namespace, so the ACL is the
// lock — the Unix-socket-0600 equivalent. It is a protected DACL (P, no
// inheritance) granting Generic All only to the creating user (OW = Owner
// Rights, S-1-3-4) and LocalSystem (SY); no ACE for Everyone or Authenticated
// Users, so no other principal can open the pipe.
const agentPipeSDDL = "D:P(A;;GA;;;OW)(A;;GA;;;SY)"

// platformListen creates the named pipe in byte mode (the agent protocol
// carries its own length-prefixed framing) with the owner-only security
// descriptor applied at creation time.
//
// Name-squatting note (applies equally to the dotvault pipe and the Pageant
// pipe served on the predictable \\.\pipe\pageant.<user>.<hash> name):
// winio.ListenPipe creates the first instance with the NT FILE_CREATE
// disposition, which fails with a name-collision error if the pipe already
// exists. So if a hostile local process pre-created the name, this returns an
// error rather than silently attaching as a second instance to a pipe the
// attacker owns — dotvault never serves over, or trusts, a pipe it did not
// create. Whichever process wins the create race owns the name; that exposure
// is inherent to the fixed Pageant namespace (real Pageant has it too) and is
// not introduced or wideneable here. The restrictive DACL below governs every
// instance dotvault does create.
func (l *Listener) platformListen() (net.Listener, error) {
	cfg := &winio.PipeConfig{
		SecurityDescriptor: agentPipeSDDL,
		MessageMode:        false,
	}
	ln, err := winio.ListenPipe(l.addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("listen pipe %s: %w", l.addr, err)
	}
	return ln, nil
}

// platformCleanup is a no-op on Windows: closing the pipe listener releases the
// namespace entry, there is no filesystem node to unlink.
func (l *Listener) platformCleanup() {}

// Pageant pipe naming. PuTTY (0.71+) and the PuTTY-family clients that reuse
// its agent code locate Pageant over a named pipe whose name is
//
//	\\.\pipe\pageant.<username>.<hash>
//
// where <username> is the bare OS account (no domain) and <hash> is the hex
// SHA-256 of the CryptProtectMemory(CROSS_PROCESS)-obfuscated window-class
// string "Pageant". This mirrors PuTTY's agent_named_pipe_name() /
// capi_obfuscate_string(); the obfuscation key is per-boot, so the suffix
// must be recomputed at runtime and cannot be hard-coded. See
// https://github.com/ndbeals/winssh-pageant/issues/1 for the reverse-engineered
// algorithm this reproduces.
const (
	pageantPipeFormat = `\\.\pipe\pageant.%s.%s`
	// pageantClassName is PuTTY's Pageant window class — the string hashed
	// into the pipe suffix.
	pageantClassName = "Pageant"

	cryptProtectMemoryBlockSize    = 16
	cryptProtectMemoryCrossProcess = 0x01
)

var (
	modCrypt32             = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectMemory = modCrypt32.NewProc("CryptProtectMemory")
)

// pageantPipeName derives the Pageant-convention named pipe for the current
// user. Empty username or an unavailable CryptProtectMemory surfaces as an
// error so the caller can fall back to the dotvault pipe alone.
func pageantPipeName() (string, error) {
	user, err := paths.Username()
	if err != nil {
		return "", fmt.Errorf("pageant pipe: %w", err)
	}
	if user == "" {
		return "", fmt.Errorf("pageant pipe: empty username")
	}
	suffix, err := capiObfuscateString(pageantClassName)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(pageantPipeFormat, user, suffix), nil
}

// capiObfuscateString reproduces PuTTY's capi_obfuscate_string: pad the input
// (plus its NUL terminator) up to a CryptProtectMemory block boundary,
// in-place CROSS_PROCESS-obfuscate it, then return the hex SHA-256 of the
// obfuscated bytes.
func capiObfuscateString(realname string) (string, error) {
	cryptlen := len(realname) + 1
	cryptlen += cryptProtectMemoryBlockSize - 1
	cryptlen /= cryptProtectMemoryBlockSize
	cryptlen *= cryptProtectMemoryBlockSize

	cryptdata := make([]byte, cryptlen)
	copy(cryptdata, realname)

	if err := procCryptProtectMemory.Find(); err != nil {
		return "", fmt.Errorf("pageant pipe: CryptProtectMemory unavailable: %w", err)
	}
	r, _, callErr := procCryptProtectMemory.Call(
		uintptr(unsafe.Pointer(&cryptdata[0])),
		uintptr(cryptlen),
		uintptr(cryptProtectMemoryCrossProcess),
	)
	if r == 0 {
		return "", fmt.Errorf("pageant pipe: CryptProtectMemory failed: %w", callErr)
	}

	hash := sha256.Sum256(cryptdata)
	return hex.EncodeToString(hash[:]), nil
}
