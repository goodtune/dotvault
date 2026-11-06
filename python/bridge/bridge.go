//go:build cgo

// Command bridge is the cgo c-shared boundary that exposes dotvault's public
// client API (github.com/goodtune/dotvault/client) to non-Go runtimes — today,
// the Python package under python/. It is built with
//
//	go build -buildmode=c-shared -o _dotvault.<ext> ./python/bridge
//
// and loaded via ctypes. It imports ONLY the public client package, never any
// internal/* package, so the same single-source-of-truth boundary the Go
// facade enforces holds for the Python surface too: token precedence, the
// OS-user identity convention, and the kv/users/<user>/... layout all come from
// the one Go implementation rather than being re-derived in Python.
//
// Scope is the read-only + cached-auth subset of the facade plus the
// peer-action surface: AuthenticateCached (never prompts), IdentityName, Token,
// ReadKVField, ReadUserSecret, ClientCertificate, and the socket-forwarded
// Browse/Notify/Clipboard, plus Subscribe (change notices over the same
// sockets; no token needed).
// Interactive Login/Authenticate (browser/terminal) are out — driving an OIDC
// browser pop or an LDAP password prompt across an FFI boundary from inside a
// Python process is awkward and is not what a library caller wants; such
// callers should rely on a token already provisioned by the daemon or `dotvault
// login`. Browse/Notify/Clipboard need no local token — they post over the peer
// socket — so they are in scope: a headless Python program hands a URL, a
// notification, or a clipboard value (a token to paste into an opened page)
// back to the workstation over the same forwarded socket it borrows tokens
// from.
//
// # ABI conventions
//
//   - A *client.Client lives entirely on the Go side. The C ABI never sees a Go
//     pointer (cgo forbids passing Go pointers that themselves contain Go
//     pointers to C); instead clients are kept in a handle table and addressed
//     by an opaque int64 handle. 0 is never a valid handle and signals failure.
//   - Strings cross out via *C.char allocated with C.CString (malloc). The
//     caller OWNS every non-nil out string and MUST release it with
//     dotvault_free. Strings cross in as NUL-terminated *C.char and are copied
//     immediately; the bridge never retains them.
//   - Fallible calls return an int category code (see the cat* constants, which
//     the Python layer mirrors) and, on a non-OK code, set *errOut to an owned
//     message string. catOK leaves *errOut nil.
//   - Network calls take a timeoutMillis; <= 0 means no deadline
//     (context.Background), matching the facade's own background-context calls.
package main

/*
#include <stdlib.h>

// dvTestSetenv / dvTestUnsetenv back the cSetenv/cUnsetenv test helpers
// portably. POSIX setenv/unsetenv are absent from the Windows CRT (mingw),
// which provides _putenv_s instead (an empty value removes the variable). These
// are used only by the bridge's tests; production syncEnv reads via getenv,
// which is standard C on every platform, so this shim is the only place a
// non-portable env call lives.
static int dvTestSetenv(const char* k, const char* v) {
#ifdef _WIN32
	return _putenv_s(k, v);
#else
	return setenv(k, v, 1);
#endif
}

static int dvTestUnsetenv(const char* k) {
#ifdef _WIN32
	return _putenv_s(k, "");
#else
	return unsetenv(k);
#endif
}

// dvWipe zeroes the NUL-terminated string at p in place. The writes go
// through a volatile pointer so the compiler cannot drop them as dead stores
// ahead of the free that follows.
static void dvWipe(char* p) {
	volatile char* v = p;
	while (*v) {
		*v++ = 0;
	}
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/goodtune/dotvault/client"
)

// facadeEnvVars are the environment variables the client facade consults:
// DOTVAULT_TOKEN (token precedence) and VAULT_NAMESPACE (honoured by the
// underlying Vault client). VAULT_TOKEN is deliberately NOT here — the facade
// ignores it on purpose.
//
// The Go runtime snapshots the process environment at init, so a value the host
// process (e.g. Python via os.environ) sets AFTER this library loads is
// invisible to os.Getenv. syncEnv re-reads each var straight from libc with
// C.getenv and pushes the current value into Go's cache, so a caller that sets
// DOTVAULT_TOKEN before authenticating gets the behaviour they expect rather
// than the stale startup snapshot. Called at every entry point that resolves a
// token or builds a Vault client.
var facadeEnvVars = []string{"DOTVAULT_TOKEN", "VAULT_NAMESPACE"}

// envMu serialises syncEnv so two concurrent entry points (e.g. two goroutines
// each building a Client) don't interleave os.Setenv/os.Unsetenv calls. This
// only guards dotvault's OWN env writes; it cannot make libc getenv/setenv safe
// against the host process mutating its environment concurrently from another
// thread (a known glibc/musl data-race class). The contract for callers is
// therefore: set DOTVAULT_TOKEN before first use, not concurrently with reads.
var envMu sync.Mutex

func syncEnv() {
	envMu.Lock()
	defer envMu.Unlock()
	for _, key := range facadeEnvVars {
		ck := C.CString(key)
		cv := C.getenv(ck)
		if cv == nil {
			_ = os.Unsetenv(key)
		} else {
			_ = os.Setenv(key, C.GoString(cv))
		}
		C.free(unsafe.Pointer(ck))
	}
}

// Error category codes returned across the ABI. These are mirrored verbatim by
// the Python layer (_errors.py) so the two stay in lockstep — extend both
// together. catOther is the catch-all for an error that matches no sentinel
// (e.g. config-load/validation failures from dotvault_client_new).
const (
	catOK              = 0
	catLoginRequired   = 1
	catDenied          = 2
	catUnreachable     = 3
	catAuthFailed      = 4
	catOther           = 5
	catPeerUnavailable = 6
	catNotConfigured   = 7
	catClosed          = 8
)

// Handle table. A *client.Client is never exposed to C directly; it is parked
// here and referenced by an int64 handle. Guarded by mu. nextID only ever
// increases, so a freed handle is never reused and a stale handle resolves to
// "unknown handle" rather than a different client.
var (
	mu      sync.Mutex
	clients = map[int64]*client.Client{}
	nextID  int64
)

func store(c *client.Client) int64 {
	mu.Lock()
	defer mu.Unlock()
	nextID++
	id := nextID
	clients[id] = c
	return id
}

// lookupID / dropID operate on plain int64 handles so they are reachable from
// cgo-free test code (a _test.go file may not import "C"). The C-typed lookup /
// drop are thin wrappers used by the exported entry points.
func lookupID(id int64) (*client.Client, bool) {
	mu.Lock()
	defer mu.Unlock()
	c, ok := clients[id]
	return c, ok
}

func dropID(id int64) {
	mu.Lock()
	defer mu.Unlock()
	delete(clients, id)
}

func lookup(h C.longlong) (*client.Client, bool) { return lookupID(int64(h)) }

func drop(h C.longlong) { dropID(int64(h)) }

// cSetenv / cUnsetenv manipulate the live libc environment the way a host
// process (Python) would. They exist so cgo-free tests can drive syncEnv
// without importing "C" themselves.
func cSetenv(key, val string) {
	ck, cv := C.CString(key), C.CString(val)
	C.dvTestSetenv(ck, cv)
	C.free(unsafe.Pointer(ck))
	C.free(unsafe.Pointer(cv))
}

func cUnsetenv(key string) {
	ck := C.CString(key)
	C.dvTestUnsetenv(ck)
	C.free(unsafe.Pointer(ck))
}

// goString copies a NUL-terminated C string into a Go string, treating a nil
// pointer as "". The bridge never retains the underlying C memory.
func goString(p *C.char) string {
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

// setErr writes an owned copy of err's message to *errOut when errOut is
// non-nil. The caller frees it with dotvault_free.
func setErr(errOut **C.char, err error) {
	if errOut != nil && err != nil {
		*errOut = C.CString(err.Error())
	}
}

// categoryOf maps a facade error onto a cat* code via the errors.Is-able
// sentinels. Order matters only in that each sentinel is distinct; a nil error
// is catOK. An error matching no sentinel (config/validation/programmer error)
// is catOther. It returns a plain int so cgo-free tests can assert on it;
// category is the C.int-returning wrapper the entry points use.
func categoryOf(err error) int {
	switch {
	case err == nil:
		return catOK
	case errors.Is(err, client.ErrLoginRequired):
		return catLoginRequired
	case errors.Is(err, client.ErrDenied):
		return catDenied
	case errors.Is(err, client.ErrUnreachable):
		return catUnreachable
	case errors.Is(err, client.ErrAuthFailed):
		return catAuthFailed
	case errors.Is(err, client.ErrPeerUnavailable):
		return catPeerUnavailable
	case errors.Is(err, client.ErrNotConfigured):
		return catNotConfigured
	case errors.Is(err, client.ErrSubscriptionClosed):
		return catClosed
	default:
		return catOther
	}
}

func category(err error) C.int { return C.int(categoryOf(err)) }

// callContext builds the context for a network call. timeoutMillis <= 0 yields
// a background context (no deadline). The returned cancel is always safe to
// call and must be deferred by the caller.
func callContext(timeoutMillis C.longlong) (context.Context, context.CancelFunc) {
	if timeoutMillis <= 0 {
		return context.WithCancel(context.Background())
	}
	return context.WithTimeout(context.Background(), time.Duration(timeoutMillis)*time.Millisecond)
}

//export dotvault_default_config_path
func dotvault_default_config_path() *C.char {
	return C.CString(client.DefaultConfigPath())
}

// dotvault_free releases an out string. It zeroes the bytes first: out
// strings carry tokens, secret values and private keys, and freed malloc
// memory is not cleared, so they would otherwise linger in the host
// process's heap until the allocator reuses the block. (The Python side's
// own copy is an immutable str it cannot clear; this covers the half the
// bridge owns.)
//
//export dotvault_free
func dotvault_free(p *C.char) {
	if p != nil {
		C.dvWipe(p)
		C.free(unsafe.Pointer(p))
	}
}

// wipedCString allocates s as an out string would be, wipes it as
// dotvault_free does, and returns the bytes left behind, for cgo-free tests.
func wipedCString(s string) []byte {
	p := C.CString(s)
	defer C.free(unsafe.Pointer(p))
	C.dvWipe(p)
	return C.GoBytes(unsafe.Pointer(p), C.int(len(s)))
}

// dotvault_client_new loads dotvault's system config from configPath (empty =>
// DefaultConfigPath) and constructs a client. A non-empty identity is applied
// as client.WithIdentity, overriding the OS-user path segment. On success it
// returns a handle > 0 and leaves *errOut nil; on failure it returns 0 and sets
// *errOut. Config-load/validation failures are not facade sentinels, so the
// category is not surfaced here — the message carries the detail.
//
//export dotvault_client_new
func dotvault_client_new(configPath *C.char, identity *C.char, errOut **C.char) C.longlong {
	syncEnv()
	path := goString(configPath)
	if path == "" {
		path = client.DefaultConfigPath()
	}
	cfg, err := client.LoadConfig(path)
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	var opts []client.Option
	if id := goString(identity); id != "" {
		opts = append(opts, client.WithIdentity(id))
	}
	c, err := client.New(cfg, opts...)
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	return C.longlong(store(c))
}

//export dotvault_client_free
func dotvault_client_free(h C.longlong) {
	drop(h)
}

// errUnknownHandle is returned for a handle absent from the table (already
// freed, or never issued). It is catOther — a programmer error, not a Vault
// condition.
var errUnknownHandle = errors.New("dotvault: unknown client handle")

//export dotvault_authenticate_cached
func dotvault_authenticate_cached(h C.longlong, timeoutMillis C.longlong, errOut **C.char) C.int {
	c, ok := lookup(h)
	if !ok {
		setErr(errOut, errUnknownHandle)
		return catOther
	}
	syncEnv()
	ctx, cancel := callContext(timeoutMillis)
	defer cancel()
	if err := c.AuthenticateCached(ctx); err != nil {
		setErr(errOut, err)
		return category(err)
	}
	return catOK
}

//export dotvault_identity_name
func dotvault_identity_name(h C.longlong, out **C.char, errOut **C.char) C.int {
	c, ok := lookup(h)
	if !ok {
		setErr(errOut, errUnknownHandle)
		return catOther
	}
	name, err := c.IdentityName()
	if err != nil {
		setErr(errOut, err)
		return category(err)
	}
	if out != nil {
		*out = C.CString(name)
	}
	return catOK
}

//export dotvault_token
func dotvault_token(h C.longlong, out **C.char, errOut **C.char) C.int {
	c, ok := lookup(h)
	if !ok {
		setErr(errOut, errUnknownHandle)
		return catOther
	}
	if out != nil {
		*out = C.CString(c.Token())
	}
	return catOK
}

// readResult writes a (value, found) read outcome across the ABI. found is set
// to 1/0. value is only allocated when found.
func readResult(value string, found bool, err error, out **C.char, foundOut *C.int, errOut **C.char) C.int {
	if err != nil {
		setErr(errOut, err)
		return category(err)
	}
	if foundOut != nil {
		if found {
			*foundOut = 1
		} else {
			*foundOut = 0
		}
	}
	if found && out != nil {
		*out = C.CString(value)
	}
	return catOK
}

//export dotvault_read_kv_field
func dotvault_read_kv_field(h C.longlong, mount, path, field *C.char, timeoutMillis C.longlong, out **C.char, foundOut *C.int, errOut **C.char) C.int {
	c, ok := lookup(h)
	if !ok {
		setErr(errOut, errUnknownHandle)
		return catOther
	}
	ctx, cancel := callContext(timeoutMillis)
	defer cancel()
	value, found, err := c.ReadKVField(ctx, goString(mount), goString(path), goString(field))
	return readResult(value, found, err, out, foundOut, errOut)
}

//export dotvault_read_user_secret
func dotvault_read_user_secret(h C.longlong, service, field *C.char, timeoutMillis C.longlong, out **C.char, foundOut *C.int, errOut **C.char) C.int {
	c, ok := lookup(h)
	if !ok {
		setErr(errOut, errUnknownHandle)
		return catOther
	}
	ctx, cancel := callContext(timeoutMillis)
	defer cancel()
	value, found, err := c.ReadUserSecret(ctx, goString(service), goString(field))
	return readResult(value, found, err, out, foundOut, errOut)
}

//export dotvault_remote_browse
func dotvault_remote_browse(h C.longlong, rawURL *C.char, timeoutMillis C.longlong, errOut **C.char) C.int {
	c, ok := lookup(h)
	if !ok {
		setErr(errOut, errUnknownHandle)
		return catOther
	}
	ctx, cancel := callContext(timeoutMillis)
	defer cancel()
	if err := c.Browse(ctx, goString(rawURL)); err != nil {
		setErr(errOut, err)
		return category(err)
	}
	return catOK
}

//export dotvault_remote_notify
func dotvault_remote_notify(h C.longlong, level, title, body, actionURL *C.char, timeoutMillis C.longlong, errOut **C.char) C.int {
	c, ok := lookup(h)
	if !ok {
		setErr(errOut, errUnknownHandle)
		return catOther
	}
	ctx, cancel := callContext(timeoutMillis)
	defer cancel()
	if err := c.Notify(ctx, goString(level), goString(title), goString(body), goString(actionURL)); err != nil {
		setErr(errOut, err)
		return category(err)
	}
	return catOK
}

//export dotvault_remote_clipboard
func dotvault_remote_clipboard(h C.longlong, text *C.char, timeoutMillis C.longlong, errOut **C.char) C.int {
	c, ok := lookup(h)
	if !ok {
		setErr(errOut, errUnknownHandle)
		return catOther
	}
	ctx, cancel := callContext(timeoutMillis)
	defer cancel()
	if err := c.Clipboard(ctx, goString(text)); err != nil {
		setErr(errOut, err)
		return category(err)
	}
	return catOK
}

// dotvault_client_certificate returns the mutual-TLS client certificate the
// client's config describes as two owned PEM strings: *certOut is the leaf
// followed by its CA chain, *keyOut is the PKCS#8 private key. On success both
// are non-nil and the caller frees each with dotvault_free; on any error both
// are left untouched (nil) and only *errOut is set. Nothing here logs, and
// errors carry no key material (the facade guarantees that).
//
// It never prompts. The facade may authenticate from the cached sources
// (token, peer socket, enrolled certificate) to sign, so syncEnv runs first.
//
//export dotvault_client_certificate
func dotvault_client_certificate(h C.longlong, timeoutMillis C.longlong, certOut, keyOut, errOut **C.char) C.int {
	c, ok := lookup(h)
	if !ok {
		setErr(errOut, errUnknownHandle)
		return catOther
	}
	syncEnv()
	ctx, cancel := callContext(timeoutMillis)
	defer cancel()
	cc, err := clientCertificate(ctx, c, certOut != nil && keyOut != nil)
	if err != nil {
		setErr(errOut, err)
		return category(err)
	}
	*certOut = C.CString(string(cc.CertPEM))
	*keyOut = C.CString(string(cc.KeyPEM))
	return catOK
}

// errNilOutput is a caller passing nowhere to put the PEM.
var errNilOutput = errors.New("dotvault: client_certificate: nil output pointer")

// clientCertificate is dotvault_client_certificate's cgo-free body. The output
// pointers are checked before ClientCertificate is called, so a caller that
// could not receive the result never triggers a signing at Vault (and never
// has a private key generated for nothing).
func clientCertificate(ctx context.Context, c *client.Client, outputsOK bool) (*client.ClientCertificate, error) {
	if !outputsOK {
		return nil, errNilOutput
	}
	return c.ClientCertificate(ctx)
}

// Subscription table, parallel to the client table and for the same reason:
// a *client.Subscription holds Go pointers, so C only ever sees an int64
// handle. nextSubID only increases, so a closed handle never names another
// subscription.
var (
	subMu     sync.Mutex
	subs      = map[int64]*client.Subscription{}
	nextSubID int64
)

func storeSub(s *client.Subscription) int64 {
	subMu.Lock()
	defer subMu.Unlock()
	nextSubID++
	subs[nextSubID] = s
	return nextSubID
}

func lookupSubID(id int64) (*client.Subscription, bool) {
	subMu.Lock()
	defer subMu.Unlock()
	s, ok := subs[id]
	return s, ok
}

func takeSubID(id int64) (*client.Subscription, bool) {
	subMu.Lock()
	defer subMu.Unlock()
	s, ok := subs[id]
	delete(subs, id)
	return s, ok
}

// errUnknownSubscription is reported as catClosed: close frees the handle, so
// a next racing a close on another thread finds it gone, and to the caller
// that is the same outcome as finding it closed.
var errUnknownSubscription = fmt.Errorf("%w (unknown subscription handle)", client.ErrSubscriptionClosed)

// eventJSON is the wire shape of one event handed to Python: the facade's
// Event with lower-case keys and an RFC 3339 time (empty when unknown).
func eventJSON(e client.Event) (string, error) {
	t := ""
	if !e.Time.IsZero() {
		t = e.Time.UTC().Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(struct {
		Key     string `json:"key"`
		Version int    `json:"version"`
		Source  string `json:"source"`
		Time    string `json:"time"`
	}{e.Key, e.Version, e.Source, t})
	return string(b), err
}

// dotvault_subscribe starts a client.Subscribe and writes its handle to
// *subOut. The subscription is independent of any call's timeout: it runs
// until dotvault_subscription_close.
//
//export dotvault_subscribe
func dotvault_subscribe(h C.longlong, subOut *C.longlong, errOut **C.char) C.int {
	c, ok := lookup(h)
	if !ok {
		setErr(errOut, errUnknownHandle)
		return catOther
	}
	s, err := c.Subscribe(context.Background())
	if err != nil {
		setErr(errOut, err)
		return category(err)
	}
	*subOut = C.longlong(storeSub(s))
	return catOK
}

// dotvault_subscription_next waits up to timeoutMillis (<= 0: indefinitely)
// for the next event. On an event it returns catOK with *out set to an owned
// JSON string; on timeout it returns catOK with *out left NULL. A closed
// subscription (including one closed from another thread while this call
// waited, or already freed by close) is catClosed.
//
//export dotvault_subscription_next
func dotvault_subscription_next(sub C.longlong, timeoutMillis C.longlong, out **C.char, errOut **C.char) C.int {
	s, ok := lookupSubID(int64(sub))
	if !ok {
		setErr(errOut, errUnknownSubscription)
		return catClosed
	}
	ctx, cancel := callContext(timeoutMillis)
	defer cancel()
	e, err := s.Next(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		return catOK
	}
	if err != nil {
		setErr(errOut, err)
		return category(err)
	}
	js, err := eventJSON(e)
	if err != nil {
		setErr(errOut, err)
		return catOther
	}
	*out = C.CString(js)
	return catOK
}

// dotvault_subscription_close stops a subscription and frees its handle. A
// Next blocked on it returns. Closing an unknown handle is a no-op.
//
//export dotvault_subscription_close
func dotvault_subscription_close(sub C.longlong) {
	if s, ok := takeSubID(int64(sub)); ok {
		_ = s.Close()
	}
}

func main() {}
