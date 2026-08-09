package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/goodtune/dotvault/internal/sshfwd"
)

// These tests exercise internal/sshfwd (daemon-managed SSH remote forwards)
// against a real OpenSSH server, not the in-memory fake sshd the package's
// own unit tests use (fakesshd_test.go). The fake models what we believe
// OpenSSH does; these tests exist to catch the next place that belief turns
// out to be wrong — see docker-compose.yaml's "sshfwd" profile for the two
// server containers and testdata/sshd for their fixtures.
const (
	sshdAddr      = "127.0.0.1:2222" // AllowStreamLocalForwarding yes
	sshdNoFwdAddr = "127.0.0.1:2223" // AllowStreamLocalForwarding no
	sshdContainer = "dotvault-sshd"
	sshdUser      = "dotvault"

	// testKeyPath is the fixture keypair's private half. Not a secret: it
	// only grants access to the throwaway, loopback-only sshd containers
	// these tests bring up locally, and its public half is baked into the
	// container image at compose-up time (see docker-compose.yaml).
	testKeyPath = "testdata/sshd/keys/dotvault_test_ed25519"
)

// skipIfNoSSHD dials addr and skips the test if nothing answers, mirroring
// skipIfNoVault (e2e_test.go). The sshd containers are opt-in via `docker
// compose --profile sshfwd up -d`, so a plain `go test ./test/integration/`
// must not fail when they are not running.
func skipIfNoSSHD(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Skipf("sshd not available at %s (run: docker compose --profile sshfwd up -d): %v", addr, err)
	}
	conn.Close()
}

// skipIfNoDockerCLI skips tests that shell out to `docker exec`/`docker
// restart` to observe or perturb the server container directly (the target
// dial is real dotvault code; only the assertions and the transport-kill
// step reach into the container). A reachable sshd implies docker was used
// to start it in the normal case, but the CLI binary itself is checked
// separately so a missing one fails as a clean skip, not a confusing exec
// error mid-test.
func skipIfNoDockerCLI(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not available")
	}
}

// testSigner parses the fixture keypair's private half, checked in at
// testKeyPath (see its doc comment for why that's fine).
func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	data, err := os.ReadFile(testKeyPath)
	if err != nil {
		t.Fatalf("read test key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		t.Fatalf("parse test key: %v", err)
	}
	return signer
}

// randSuffix returns a short random hex string so concurrent/successive
// test runs don't collide on the same remote socket path.
func randSuffix(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// shortTempDir returns a fresh directory under /tmp directly, not
// t.TempDir(): this host's $TMPDIR exceeds the 104-byte sun_path budget for
// Unix domain sockets, which breaks any test that binds one under it.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "dv-")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// newUnixTarget stands up an httptest.Server bound to a Unix socket instead
// of its default TCP listener, always answering body on any path. This is
// the "local target" a forward relays to — the subject under test is the
// forward, not dotvault's real web API, so a trivial handler is enough.
func newUnixTarget(t *testing.T, body string) (socketPath string) {
	t.Helper()
	dir := shortTempDir(t)
	socketPath = filepath.Join(dir, "target.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix target: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	srv.Listener.Close() // discard the TCP listener NewUnstartedServer created
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	return socketPath
}

// dialUnix returns an sshfwd.Dialer that connects to a local Unix socket —
// the Deps.Target a real daemon would point at its own web API.
func dialUnix(socketPath string) sshfwd.Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}
}

// insecurePolicy returns a Deps.Policy that trusts whatever host key is
// offered. Host-key trust itself is exercised by
// TestVerifyReturnsFingerprintForUnknownHost; the forwarding-lifecycle tests
// have nothing to do with it and use this to stay out of the way.
func insecurePolicy(sshfwd.Remote) *sshfwd.HostKeyPolicy {
	return &sshfwd.HostKeyPolicy{Insecure: true}
}

func testDeps(t *testing.T, targetSocket string) sshfwd.Deps {
	signer := testSigner(t)
	return sshfwd.Deps{
		Signers:    func() ([]ssh.Signer, error) { return []ssh.Signer{signer}, nil },
		User:       func() (string, error) { return sshdUser, nil },
		Target:     dialUnix(targetSocket),
		TargetName: "test-target",
		Policy:     insecurePolicy,
	}
}

// dialSSHD opens a direct *ssh.Client to the given port, bypassing
// sshfwd.Manager — used by the tests that drive sshfwd.ServeForward directly
// rather than through the full reconnect-managing run loop.
func dialSSHD(t *testing.T, port int) *ssh.Client {
	t.Helper()
	cl, err := sshfwd.Dial(context.Background(), sshfwd.DialConfig{
		Host:    "127.0.0.1",
		Port:    port,
		User:    sshdUser,
		Signers: []ssh.Signer{testSigner(t)},
		HostKey: insecurePolicy(sshfwd.Remote{}),
	})
	if err != nil {
		t.Fatalf("dial 127.0.0.1:%d: %v", port, err)
	}
	return cl
}

// dockerExec runs `docker exec <container> <args...>` and fails the test on
// a non-zero exit.
func dockerExec(t *testing.T, container string, args ...string) string {
	t.Helper()
	out, err := dockerExecOutput(container, args...)
	if err != nil {
		t.Fatalf("docker exec %s %s: %v: %s", container, strings.Join(args, " "), err, out)
	}
	return out
}

// dockerExecOutput is dockerExec without the fatal exit, for callers that
// need to poll and tolerate transient failures (e.g. curl against a socket
// that hasn't finished being reclaimed yet).
func dockerExecOutput(container string, args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"exec", container}, args...)...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// waitForRemoteSocket polls, from inside container, for a Unix socket to
// exist at path. ListenUnix (the streamlocal-forward@openssh.com global
// request) has already been acknowledged by sshd by the time it returns to
// the caller, so in practice this resolves on the first or second poll; it
// exists so the test observes the real filesystem state rather than
// assuming a fixed delay.
func waitForRemoteSocket(t *testing.T, container, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := dockerExecOutput(container, "test", "-S", path); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("remote socket %s never appeared on %s", path, container)
}

// curlUntil polls, from inside container, until a GET against the Unix
// socket at socketPath returns want, or times out. Used instead of a single
// curl attempt so a transient "connection refused" while a forward is still
// coming up (or being reclaimed) doesn't flake the test.
func curlUntil(t *testing.T, container, socketPath, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastOut string
	var lastErr error
	for time.Now().Before(deadline) {
		out, err := dockerExecOutput(container, "curl", "-s", "--max-time", "2", "--unix-socket", socketPath, "http://dotvault-sshfwd-test/")
		if err == nil && out == want {
			return
		}
		lastOut, lastErr = out, err
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("curl --unix-socket %s never returned %q within %s (last: out=%q err=%v)", socketPath, want, timeout, lastOut, lastErr)
}

// removeRemoteSocket best-effort unlinks path in container, for test cleanup.
func removeRemoteSocket(container, path string) {
	_, _ = dockerExecOutput(container, "rm", "-f", path)
}

// testCommandRunner satisfies sshfwd.CommandRunner over a plain *ssh.Client,
// mirroring the unexported sshRunner forward.go uses internally. Tests use
// it to resolve a "~/"-prefixed remote_socket through the same
// sshfwd.ExpandRemotePath production code takes, rather than guessing the
// linuxserver/openssh-server image's home directory or shelling into the
// container as the wrong user (`docker exec` defaults to root, not the
// "dotvault" account the SSH connection authenticates as — those two do not
// share a $HOME on this image).
type testCommandRunner struct{ cl *ssh.Client }

func (r testCommandRunner) Run(ctx context.Context, cmd string) (string, error) {
	sess, err := r.cl.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.Output(cmd)
	return string(out), err
}

// resolveRemoteSocket expands a "~/"-prefixed remote_socket against the
// account a real forward would authenticate as, via a throwaway connection.
func resolveRemoteSocket(t *testing.T, port int, remoteSocket string) string {
	t.Helper()
	cl := dialSSHD(t, port)
	defer cl.Close()
	resolved, err := sshfwd.ExpandRemotePath(context.Background(), testCommandRunner{cl: cl}, remoteSocket)
	if err != nil {
		t.Fatalf("ExpandRemotePath(%s): %v", remoteSocket, err)
	}
	return resolved
}

// restartContainer kills and restarts container with a short graceful
// timeout, simulating "the SSH transport dies" without tearing down the
// whole test's docker-compose stack. `-t 1` keeps the kill prompt: the
// default 10s graceful-stop window would otherwise leave dotvault's
// reconnect logic to notice the dead transport well before the container
// process actually exits, muddying what "restore" means for the test that
// waits on it.
func restartContainer(t *testing.T, container string) {
	t.Helper()
	out, err := exec.Command("docker", "restart", "-t", "1", container).CombinedOutput()
	if err != nil {
		t.Fatalf("docker restart %s: %v: %s", container, err, out)
	}
}

// waitForState polls mgr.Status() for host until it reports want or timeout
// elapses, returning the last-seen status either way. Used instead of a
// fixed sleep so the test observes the actual state transition.
func waitForState(t *testing.T, mgr *sshfwd.Manager, host string, want sshfwd.State, timeout time.Duration) sshfwd.RemoteStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last sshfwd.RemoteStatus
	for time.Now().Before(deadline) {
		for _, st := range mgr.Status() {
			if strings.EqualFold(st.Host, host) {
				last = st
				if st.State == string(want) {
					return st
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("host %s did not reach state %q within %s (last observed: %+v)", host, want, timeout, last)
	return sshfwd.RemoteStatus{}
}

// statePoller continuously samples a managed remote's state at a resolution
// fine enough to catch a transition that only holds for a few hundred
// milliseconds (Reconnecting, in particular — see remote.go: it is set once,
// immediately after the live connection dies, and only lasts as long as
// that attempt's backoff sleep before the run loop moves on to Connecting).
// A test that only polled for the state it expects *next* could easily step
// over a state that came and went between polls; this records the whole
// sequence so the assertion is against what was actually observed, not
// inferred from having arrived at the next expected state.
type statePoller struct {
	mu     sync.Mutex
	seen   []sshfwd.State
	stopCh chan struct{}
	doneCh chan struct{}
}

func startStatePoller(mgr *sshfwd.Manager, host string) *statePoller {
	p := &statePoller{stopCh: make(chan struct{}), doneCh: make(chan struct{})}
	go func() {
		defer close(p.doneCh)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		var last sshfwd.State
		for {
			select {
			case <-p.stopCh:
				return
			case <-ticker.C:
				for _, st := range mgr.Status() {
					if strings.EqualFold(st.Host, host) {
						s := sshfwd.State(st.State)
						if s != last {
							p.mu.Lock()
							p.seen = append(p.seen, s)
							p.mu.Unlock()
							last = s
						}
					}
				}
			}
		}
	}()
	return p
}

func (p *statePoller) history() []sshfwd.State {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]sshfwd.State, len(p.seen))
	copy(out, p.seen)
	return out
}

func (p *statePoller) stop() {
	close(p.stopCh)
	<-p.doneCh
}

func containsState(hist []sshfwd.State, want sshfwd.State) bool {
	for _, s := range hist {
		if s == want {
			return true
		}
	}
	return false
}

// TestForwardReachesLocalTarget covers case 1: bind the remote socket over a
// real SSH transport, and reach the local target through it — the way a
// process on the sshd host would, over curl --unix-socket, not merely by
// dialing back through the same *ssh.Client this test happens to hold.
func TestForwardReachesLocalTarget(t *testing.T) {
	skipIfNoSSHD(t, sshdAddr)
	skipIfNoDockerCLI(t)

	const body = "hello from the local target"
	targetSocket := newUnixTarget(t, body)

	cl := dialSSHD(t, 2222)
	defer cl.Close()

	socket := fmt.Sprintf("/config/dv-test-%s.sock", randSuffix(t))
	t.Cleanup(func() { removeRemoteSocket(sshdContainer, socket) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- sshfwd.ServeForward(ctx, cl, "test-host", socket, dialUnix(targetSocket), nil)
	}()

	waitForRemoteSocket(t, sshdContainer, socket)
	curlUntil(t, sshdContainer, socket, body, 5*time.Second)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServeForward returned %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeForward did not return after context cancellation")
	}
}

// TestForwardReconnectsAfterTransportLoss covers cases 2 and 3: kill the SSH
// transport out from under a live, daemon-managed forward, confirm the
// remote is reported reconnecting, then confirm it reconnects on its own and
// a *new* connection through the (necessarily re-bound) socket succeeds.
//
// This runs through sshfwd.Manager end to end (not a bare ServeForward call
// like TestForwardReachesLocalTarget), because Reconnecting/Connected are
// ManagedRemote's states — they only exist on the dial-forward-keepalive-
// backoff run loop, not on ServeForward in isolation.
func TestForwardReconnectsAfterTransportLoss(t *testing.T) {
	skipIfNoSSHD(t, sshdAddr)
	skipIfNoDockerCLI(t)

	const body = "hello after reconnect"
	targetSocket := newUnixTarget(t, body)

	// "~/"-prefixed, unlike the other tests here, so this also exercises
	// ExpandRemotePath's $HOME probe (home.go) against a real sshd, on the
	// path a production remote actually takes (run(), not a bare Verify or
	// ServeForward call).
	remoteSocket := fmt.Sprintf("~/.ssh/dv-test-%s.sock", randSuffix(t))
	remote := sshfwd.Remote{Host: "127.0.0.1", Port: 2222, RemoteSocket: remoteSocket}

	mgr := sshfwd.NewManager(context.Background(), testDeps(t, targetSocket))
	t.Cleanup(mgr.Close)

	poller := startStatePoller(mgr, remote.Host)
	defer poller.stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mgr.Reconcile(ctx, []sshfwd.Remote{remote}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	waitForState(t, mgr, remote.Host, sshfwd.StateConnected, 15*time.Second)

	resolved := resolveRemoteSocket(t, 2222, remoteSocket)
	t.Cleanup(func() { removeRemoteSocket(sshdContainer, resolved) })
	waitForRemoteSocket(t, sshdContainer, resolved)
	curlUntil(t, sshdContainer, resolved, body, 5*time.Second)

	// Kill the transport: restart the container out from under the live
	// connection, rather than anything client-side, so this is a genuine
	// transport death and not a graceful shutdown dotvault initiated
	// itself. Confirmed separately (see the report) that this leaves the
	// remote socket file behind exactly like a crashed session would — so
	// recovery below also exercises the stale-socket reclaim path for
	// real, on top of the dedicated TestForwardReclaimsStaleSocket.
	restartContainer(t, sshdContainer)

	// Recover, and only then look at what was observed in between: the
	// Reconnecting state is set once, immediately, and only holds for one
	// backoff sleep (hundreds of ms) before the run loop moves on to
	// Connecting — see statePoller's doc comment for why this is polled
	// continuously rather than waited for directly.
	waitForState(t, mgr, remote.Host, sshfwd.StateConnected, 60*time.Second)

	if hist := poller.history(); !containsState(hist, sshfwd.StateReconnecting) {
		t.Errorf("state history never included %q: %v", sshfwd.StateReconnecting, hist)
	}

	// A new connection through the socket must succeed post-recovery — not
	// merely "the manager says Connected", but the forward actually works
	// again, at the same resolved path (the remote account's $HOME did not
	// move, so the reclaim must have landed on the exact same file the
	// crashed session left behind).
	resolvedAfter := resolveRemoteSocket(t, 2222, remoteSocket)
	if resolvedAfter != resolved {
		t.Fatalf("resolved remote socket path changed across reconnect: %s -> %s", resolved, resolvedAfter)
	}
	waitForRemoteSocket(t, sshdContainer, resolved)
	curlUntil(t, sshdContainer, resolved, body, 10*time.Second)
}

// TestForwardReclaimsStaleSocket covers case 4: a socket file left behind by
// a crashed session (proven, not assumed, to be what a real crash leaves —
// see the report) must not permanently block a fresh bind at the same path.
// sshd_config.d/allow sets StreamLocalBindUnlink no deliberately, so a naive
// second bind gets EADDRINUSE and it is dotvault's own
// liveListenerAt/removeRemoteFile logic (forward.go) — not sshd — that has
// to notice nothing is listening and reclaim the path.
func TestForwardReclaimsStaleSocket(t *testing.T) {
	skipIfNoSSHD(t, sshdAddr)
	skipIfNoDockerCLI(t)

	socket := fmt.Sprintf("/config/dv-test-%s.sock", randSuffix(t))
	t.Cleanup(func() { removeRemoteSocket(sshdContainer, socket) })

	// Simulate the crashed session: bind, then sever the transport
	// uncleanly (Close, not a graceful cancel-streamlocal-forward global
	// request) so sshd never gets a chance to unlink the socket itself.
	staleClient := dialSSHD(t, 2222)
	if _, err := staleClient.ListenUnix(socket); err != nil {
		t.Fatalf("bind stale socket: %v", err)
	}
	staleClient.Close()
	waitForRemoteSocket(t, sshdContainer, socket)

	const body = "reclaimed"
	targetSocket := newUnixTarget(t, body)

	cl := dialSSHD(t, 2222)
	defer cl.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sshfwd.ServeForward(ctx, cl, "test-host", socket, dialUnix(targetSocket), nil)
	}()

	// The first ListenUnix attempt inside ServeForward is expected to fail
	// EADDRINUSE and trigger the reclaim path; curlUntil's polling absorbs
	// the time that takes (the live-listener probe, then the remote rm -f,
	// then the retried bind) rather than the test needing to know how long
	// it should take.
	curlUntil(t, sshdContainer, socket, body, 10*time.Second)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ServeForward returned %v after cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeForward did not return after context cancellation")
	}
}

// TestVerifyRefusesWhenForwardingDisabled covers case 5: against a real sshd
// with AllowStreamLocalForwarding no, Registry.Add's live verification must
// fail and ssh.yaml must end up with nothing written — Add is transactional,
// so a verification failure must leave no trace.
//
// This is also where the real server disagrees with the in-memory fake in a
// way worth calling out — see the report: a real sshd rejects a
// client-initiated direct-streamlocal open with the exact same
// ConnectionFailed reason code whether nothing is listening or
// AllowStreamLocalForwarding forbids it outright, which is precisely the
// ambiguity ServeForward's and liveListenerAt's doc comments (forward.go)
// warn about. Verify's own bind-failure fallback (verify.go) treats that
// ambiguity as inconclusive rather than guessing, which is what this test
// confirms end to end.
func TestVerifyRefusesWhenForwardingDisabled(t *testing.T) {
	skipIfNoSSHD(t, sshdNoFwdAddr)

	deps := sshfwd.Deps{
		Signers: func() ([]ssh.Signer, error) { return []ssh.Signer{testSigner(t)}, nil },
		User:    func() (string, error) { return sshdUser, nil },
		Policy:  insecurePolicy,
	}
	mgr := sshfwd.NewManager(context.Background(), deps)
	t.Cleanup(mgr.Close)

	dir := shortTempDir(t)
	sshYAML := filepath.Join(dir, "ssh.yaml")
	registry := sshfwd.NewRegistry(sshYAML, mgr, sshfwd.NewVerifier(deps))

	remote := sshfwd.Remote{Host: "127.0.0.1", Port: 2223, RemoteSocket: "/config/dv-test-noforward.sock"}
	_, err := registry.Add(context.Background(), remote, sshfwd.AddOptions{})
	if err == nil {
		t.Fatal("Add succeeded against a server with AllowStreamLocalForwarding no; want an error")
	}
	if !errors.Is(err, sshfwd.ErrBind) {
		t.Errorf("Add error = %v, want errors.Is(err, sshfwd.ErrBind)", err)
	}

	if _, statErr := os.Stat(sshYAML); !os.IsNotExist(statErr) {
		t.Errorf("%s was created despite a failed Add; verification must be transactional", sshYAML)
	}
}

// TestVerifyReturnsFingerprintForUnknownHost covers case 6: a host with no
// pinned key and no covering certificate authority must come back as a
// confirmable result (nil error, a fingerprint to show a human), not an
// error — and Registry.Add must refuse to persist it without that
// fingerprint being echoed back.
func TestVerifyReturnsFingerprintForUnknownHost(t *testing.T) {
	skipIfNoSSHD(t, sshdAddr)

	deps := sshfwd.Deps{
		Signers: func() ([]ssh.Signer, error) { return []ssh.Signer{testSigner(t)}, nil },
		User:    func() (string, error) { return sshdUser, nil },
		Policy: func(sshfwd.Remote) *sshfwd.HostKeyPolicy {
			return &sshfwd.HostKeyPolicy{} // no pin, no CAs, not insecure: genuinely unknown
		},
	}
	v := sshfwd.NewVerifier(deps)

	remote := sshfwd.Remote{Host: "127.0.0.1", Port: 2222, RemoteSocket: "/config/dv-test-unknown.sock"}
	result, err := v.Verify(context.Background(), remote, sshfwd.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil (an unknown host key is confirmable, not an error)", err)
	}
	if !result.Verified {
		t.Error("Verified = false, want true: reaching the confirmation gate counts as an actual check")
	}
	if result.Fingerprint == "" {
		t.Error("Fingerprint is empty, want the offered host key's SHA256 fingerprint")
	}
	if result.HostKey == "" {
		t.Error("HostKey is empty, want the offered key in authorized_keys form")
	}

	dir := shortTempDir(t)
	sshYAML := filepath.Join(dir, "ssh.yaml")
	mgr := sshfwd.NewManager(context.Background(), deps)
	t.Cleanup(mgr.Close)
	registry := sshfwd.NewRegistry(sshYAML, mgr, v)

	_, addErr := registry.Add(context.Background(), remote, sshfwd.AddOptions{})
	var confirm *sshfwd.HostKeyConfirmation
	if !errors.As(addErr, &confirm) {
		t.Fatalf("Add error = %v, want *sshfwd.HostKeyConfirmation", addErr)
	}
	if confirm.Fingerprint != result.Fingerprint {
		t.Errorf("confirmation fingerprint = %s, want %s", confirm.Fingerprint, result.Fingerprint)
	}
	if _, statErr := os.Stat(sshYAML); !os.IsNotExist(statErr) {
		t.Errorf("%s was created despite an unconfirmed host key", sshYAML)
	}
}
