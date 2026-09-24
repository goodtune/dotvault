// TODO(pre-1.0, #172): delete this file. It exists only to move fleets
// off the shared ~/.ssh/dotvault.sock forward without a human touching each
// workstation.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/peer"
	"github.com/goodtune/dotvault/internal/sshfwd"
)

// remoteSocketTemplateSince is the first release whose sshfwd expands
// {{HOSTNAME}}. A peer reporting an older version is left alone: handing it
// the template would bind a literal-braced socket.
//
// RELEASE REQUIREMENT: this constant must equal the release that actually
// ships {{HOSTNAME}} expansion, so the branch introducing it has to be tagged
// v0.34.0. Ship it under any lower tag and every peer fails the version gate —
// the migration then never fires anywhere, and says so only at debug level, so
// a whole fleet would quietly stay on the shared default socket with nothing in
// the logs to suggest why. Not covered by a test: main.version is injected at
// link time, so no unit test can see the tag this builds under.
const remoteSocketTemplateSince = "0.34.0"

// legacyRemoteSocket is the pre-0.34 default, the only stored value the
// migration touches. An absolute spelling of the same path is an operator's
// deliberate choice, not the untouched default, so it is left alone.
//
// It is the workstation's ssh.yaml remote_socket, and config.LegacyPeerSocket
// is this host's borrow pattern for the same forward — the same path seen from
// the two ends, which is why the migrator can be pointed at the expansion of
// either. Deliberately two constants: they are removed on different schedules.
const legacyRemoteSocket = config.LegacyPeerSocket

// migrateTimeout bounds the whole background exchange (status, list, csrf,
// patch) so a hung peer cannot leave a goroutine parked for the daemon's
// lifetime.
const migrateTimeout = 15 * time.Second

// migrateReconcileDelay is the window the workstation is asked to hold its
// forwards still for after saving the patch. Long enough for the PATCH
// response to travel back over the connection that is about to be rebound,
// short enough that the running set is only briefly out of step with the file.
const migrateReconcileDelay = 10 * time.Second

// migrateConfirmWait and migrateConfirmPoll bound the wait for the renamed
// socket to appear and answer. They are vars, not consts, purely so a test can
// shorten them: nothing else assigns to them.
//
// The wait is generous because the workstation has to run out its own
// reconcile delay, tear the old connection down and dial the new forward, and
// an SSH reconnect on a slow link is not instant. Expiring is not a failure —
// it means the migration is unconfirmed, and the next reconnect re-checks the
// workstation's configuration.
var (
	migrateConfirmWait = 45 * time.Second
	migrateConfirmPoll = 500 * time.Millisecond
)

// migrateProbeTimeout bounds a single status request against the renamed
// socket. A socket that exists but has nobody behind it (a stale node the
// forward has not rebound yet) must not consume the whole confirmation window
// on one attempt.
const migrateProbeTimeout = 3 * time.Second

// maxMigratedIdentities bounds the once-per-identity bookkeeping. A daemon
// only ever sees one old-default socket path, re-created each time the forward
// reconnects, so 64 is many reconnects' worth of history; past that the oldest
// entry is dropped, which at worst costs one extra attempt against a socket
// nothing has seen in a very long time.
const maxMigratedIdentities = 64

// peerMigrator PATCHes a workstation's managed-forward entry for this host
// from the old shared default to the per-hostname template, over the very
// socket that forward created. It is daemon-only and runs at most once per
// socket identity per process.
type peerMigrator struct {
	oldDefault string   // expanded $HOME/.ssh/dotvault.sock
	patterns   []string // this host's expanded borrow patterns

	// outcome, when set, is told how each migrated host's confirmation ended.
	// Nil in production — the logs are the product there — and set by tests,
	// which must not have to parse log output to see whether the renamed
	// socket was ever proved to work.
	outcome func(host string, confirmed bool)

	mu    sync.Mutex
	done  map[peerIdentity]bool
	order []peerIdentity // insertion order, for the bound above
}

// peerIdentity is the device/inode pair behind a socket node. Keying on it
// rather than on the path means a forward that reconnected — a new inode at
// the same path — earns one more attempt, while a failed attempt against the
// socket still sitting there is not retried.
type peerIdentity struct{ dev, ino uint64 }

// newPeerMigrator builds the migrator. patterns is this host's expanded borrow
// pattern list (peer.Pool.Patterns), which the migration needs because the
// rename it triggers moves the socket it is talking through: a host with no
// pattern covering the new name would lose its only token source. See
// canFindRenamedSocket.
func newPeerMigrator(oldDefault string, patterns []string) *peerMigrator {
	return &peerMigrator{
		oldDefault: oldDefault,
		patterns:   append([]string(nil), patterns...),
		done:       make(map[peerIdentity]bool),
	}
}

// renamedSocket is the exact path the workstation's forward will bind once it
// expands {{HOSTNAME}} with label — the same directory as the old default,
// since only the filename changes.
func (m *peerMigrator) renamedSocket(label string) string {
	return filepath.Join(filepath.Dir(m.oldDefault), "dotvault."+label+".sock")
}

// canFindRenamedSocket reports whether any of this host's borrow patterns
// would match the socket the workstation is about to rename its forward to.
//
// This is the guard against the migration severing its own borrow source. A
// config that spells the pre-list default as a one-element list — which every
// pre-0.34 guide showed as a scalar, and which an operator may equally have
// written out as a list — matches only ~/.ssh/dotvault.sock. Migrate on that
// host and the forward rebinds to a name nothing in the list matches, leaving
// no token source and nothing to recover it: the borrow that would have
// noticed can no longer happen. config.ExpandLegacyScalar handles the scalar
// spelling; an explicit one-element list is the operator's own words, so it is
// left alone and this refusal is what keeps it safe.
//
// label is the workstation's own hostname label, read from its status
// response. The check is against the exact path that produces and nothing
// else: an earlier version probed a stand-in "x" on the reasoning that the
// question was only whether a glob covered the shape, and that is wrong. A
// pattern can match the stand-in and miss the real name — `dotvault.?.sock`
// and `dotvault.[a-z].sock` both match "x" and neither matches "desktop" —
// so the stand-in could pass a host whose one and only token source the
// migration was about to move out of reach.
func (m *peerMigrator) canFindRenamedSocket(label string) bool {
	if label == "" {
		return false
	}
	expected := m.renamedSocket(label)
	for _, pat := range m.patterns {
		// A malformed pattern reports an error and no match; nothing to do
		// about it here, and the pool has already logged it.
		if ok, _ := filepath.Match(pat, expected); ok {
			return true
		}
	}
	return false
}

// claim records id as handled and reports whether this caller is the one that
// got to it first. Marking before the attempt rather than after is deliberate:
// a failure is not retried until the socket is re-created, which is the only
// event that makes a different answer likely.
func (m *peerMigrator) claim(id peerIdentity) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done[id] {
		return false
	}
	m.done[id] = true
	m.order = append(m.order, id)
	if len(m.order) > maxMigratedIdentities {
		delete(m.done, m.order[0])
		m.order = m.order[1:]
	}
	return true
}

// migratingBorrower wraps a pool so every successful borrow through the old
// default socket schedules a migration check. It exists because the lifecycle
// manager and internal/auth borrow through the Borrower seam and never see a
// path: wrapping the pool is how the daemon observes which member answered
// without internal/peer learning anything about the migration.
type migratingBorrower struct {
	pool *peer.Pool
	mig  *peerMigrator
}

var _ peer.Borrower = (*migratingBorrower)(nil)

func (b *migratingBorrower) Borrow(ctx context.Context) (string, string) {
	token, source := b.pool.Borrow(ctx)
	if token != "" {
		b.mig.maybeMigrate(ctx, source)
	}
	return token, source
}

// maybeMigrate runs the migration in the background when source is the old
// default socket and this identity has not been handled yet. Nil-safe, and
// never blocks its caller: it sits on the borrow path, which a login and the
// lifecycle poll both wait on.
//
// A migration whose outcome could not be confirmed — the PATCH response was
// lost, or the renamed socket never appeared — is retried safely rather than
// repeated blindly. The latch is per socket identity, so the next time the
// old-default socket is re-created (a new inode: the forward reconnected,
// which is also the event that would follow a workstation that never applied
// the patch) the whole exchange runs again from the workstation's *current*
// configuration. The candidate filter is exact-default-only, so a re-run
// against an entry that did migrate finds nothing to do and patches nothing.
func (m *peerMigrator) maybeMigrate(ctx context.Context, source string) {
	if m == nil || source == "" || source != m.oldDefault {
		return
	}
	id, ok := socketIdentity(source)
	if !ok {
		return
	}
	if !m.claim(id) {
		return
	}

	go func() {
		// WithoutCancel: the borrow's ctx is frequently a short per-attempt
		// bound (a lifecycle poll, a login), and the migration must outlive
		// it — the exchange is four round trips, not one. migrateTimeout is
		// the bound that matters here.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), migrateTimeout)
		defer cancel()
		if err := m.migrate(ctx, source); err != nil {
			slog.Warn("could not migrate peer forward off the shared default socket", "socket", source, "error", err)
		}
	}()
}

func (m *peerMigrator) migrate(ctx context.Context, socket string) error {
	client, _, err := peer.Client(socket)
	if err != nil {
		return err
	}

	var status struct {
		Version string `json:"version"`
		// HostnameLabel is what the peer expands {{HOSTNAME}} to, so this
		// host can work out the exact path the forward is about to move to.
		HostnameLabel string `json:"hostname_label"`
	}
	if err := getJSON(ctx, client, "/api/v1/status", &status); err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if !versionAtLeast(status.Version, remoteSocketTemplateSince) {
		slog.Debug("peer too old for {{HOSTNAME}} forwards; leaving its default socket alone", "socket", socket, "peer_version", status.Version)
		return nil
	}

	// Checked before the remotes list is fetched: it costs no network, and
	// refusing early keeps the WARN about this host's own configuration
	// separate from anything the peer reports.
	if status.HostnameLabel == "" {
		// Conservative by design: without the label there is no way to know
		// the path the forward will move to, so there is no way to know this
		// host still has a pattern matching it. Refusing costs a migration
		// that the next reconnect can attempt again; guessing costs the only
		// token source this host has.
		slog.Warn("not migrating the peer forward: the peer did not report its hostname label, so the renamed socket cannot be checked against vault.token_socket",
			"socket", socket, "patterns", m.patterns)
		return nil
	}
	expected := m.renamedSocket(status.HostnameLabel)
	if !m.canFindRenamedSocket(status.HostnameLabel) {
		slog.Warn("not migrating the peer forward: vault.token_socket has no pattern matching the renamed socket, so this host would lose its only token source; add "+config.PerHostPeerSocketGlob+" to vault.token_socket",
			"socket", socket, "expected_socket", expected, "patterns", m.patterns)
		return nil
	}

	var list struct {
		Remotes []struct {
			Host         string `json:"host"`
			RemoteSocket string `json:"remote_socket"`
		} `json:"remotes"`
	}
	if err := getJSON(ctx, client, "/api/v1/ssh/remotes", &list); err != nil {
		return fmt.Errorf("list remotes: %w", err)
	}

	var asked []string
	for _, r := range list.Remotes {
		if r.RemoteSocket != legacyRemoteSocket || !hostIsSelf(ctx, r.Host) {
			continue
		}
		if err := m.patch(ctx, client, r.Host); err != nil {
			return fmt.Errorf("patch %s: %w", r.Host, err)
		}
		asked = append(asked, r.Host)
	}
	if len(asked) > 0 {
		// One wait covers every patched entry: aliases for this machine are
		// separate entries on the same workstation, so they all rename to the
		// same socket path.
		m.confirm(ctx, asked, expected)
	}
	return nil
}

// patch asks the peer to rename one entry's remote_socket, telling it to defer
// the reconcile so this response can get home before the forward carrying it
// is rebound. It returns an error only for a refusal the peer articulated; a
// lost response is not one, and is resolved by the confirmation wait instead.
func (m *peerMigrator) patch(ctx context.Context, client *http.Client, host string) error {
	csrf, err := sshCSRFToken(ctx, client, "http://localhost")
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{
		"remote_socket": sshfwd.DefaultRemoteSocket,
		// Without this the peer saves and reconciles in one breath, tearing
		// down the connection carrying the reply — leaving this end unable to
		// tell an applied patch from a peer that died.
		"reconcile_delay": migrateReconcileDelay.String(),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
		"http://localhost/api/v1/ssh/remotes/"+url.PathEscape(host), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		// The deferred reconcile makes this rare rather than routine — the
		// response is meant to arrive well before the forward moves — but a
		// connection can still be lost for ordinary reasons. It is no longer
		// ambiguous: the renamed socket answering is the evidence, and the
		// confirmation wait goes looking for it either way.
		slog.Info("peer forward migration request did not return a response; waiting for the renamed socket", "host", host, "error", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("peer returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	slog.Info("peer accepted forward migration; waiting for the renamed socket", "host", host, "socket", sshfwd.DefaultRemoteSocket)
	return nil
}

// confirm waits for the renamed socket to appear and answer, then says so for
// every host that was asked.
//
// This is what replaces the old "probably applied" hedge. The question is not
// whether the PATCH returned but whether this host can still borrow, and only
// a live status response over the new path answers it. Failing to see one is
// reported as uncertain rather than failed: the workstation may well have
// applied the change, and the next reconnect re-checks its configuration
// either way.
func (m *peerMigrator) confirm(ctx context.Context, hosts []string, expected string) {
	// Detached and separately bounded: migrateTimeout bounds the exchange,
	// and the wait for a forward to be torn down and re-established is a
	// different, much longer thing.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), migrateConfirmWait)
	defer cancel()

	ok := m.awaitSocket(ctx, expected)
	for _, host := range hosts {
		if ok {
			slog.Info("peer forward migration confirmed", "host", host, "socket", expected)
		} else {
			slog.Warn("peer forward migration uncertain: the renamed socket did not appear; the next reconnect re-checks the peer's configuration",
				"host", host, "expected_socket", expected)
		}
		if m.outcome != nil {
			m.outcome(host, ok)
		}
	}
}

// awaitSocket polls until expected is a socket that answers a status request,
// or ctx expires.
func (m *peerMigrator) awaitSocket(ctx context.Context, expected string) bool {
	for {
		if probePeerSocket(ctx, expected) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(migrateConfirmPoll):
		}
	}
}

// probePeerSocket reports whether path is a socket node with a dotvault daemon
// answering behind it. The node existing is not enough: a forward that has not
// rebound yet can leave one lying about, and this host's whole reason for
// caring is that it can borrow through the new path.
func probePeerSocket(ctx context.Context, path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return false
	}
	client, _, err := peer.Client(path)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, migrateProbeTimeout)
	defer cancel()
	var status struct {
		Version string `json:"version"`
	}
	return getJSON(ctx, client, "/api/v1/status", &status) == nil
}

func getJSON(ctx context.Context, client *http.Client, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost"+path, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %d", path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// versionAtLeast reports whether v (a dotvault version string, optional
// leading v, optional -prerelease/+build suffix) is at least min. Anything
// that does not parse as major.minor.patch — "", "dev", a bare commit — is
// treated as new: those are development builds, which always carry the
// template support.
func versionAtLeast(v, min string) bool {
	pv, ok := parseSemver(v)
	if !ok {
		return true
	}
	pm, ok := parseSemver(min)
	if !ok {
		// min is a compile-time constant in this package, so this is
		// unreachable short of a typo in it. Fail open rather than silently
		// treating every peer as too old and migrating nothing.
		return true
	}
	for i := 0; i < 3; i++ {
		if pv[i] != pm[i] {
			return pv[i] > pm[i]
		}
	}
	return true
}

func parseSemver(s string) ([3]int, bool) {
	var out [3]int
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// lookupHost is the name-resolution seam hostIsSelf goes through. It is a
// package-level var so a test can answer without touching the network: the real
// resolver's verdict on a given name depends on the host's search domains and
// nameservers, and even a negative answer costs a round trip (up to the timeout
// below). Production behaviour is net.DefaultResolver, unchanged.
var lookupHost = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// hostIsSelf reports whether host names this machine: equal (case-folded)
// to os.Hostname() or its first label, or resolving to a non-loopback
// address one of this machine's interfaces carries. Loopback never matches —
// it would match every borrower.
func hostIsSelf(ctx context.Context, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}
	// Loopback is rejected up front, not just in the address branch below.
	// The address branch is where the real hazard lives — every machine
	// resolves loopback to itself, so admitting it would make every borrower
	// claim every loopback entry — but a box whose own os.Hostname() is
	// "localhost" (a container, a half-configured VM) would otherwise slip
	// through the name branch and rename the workstation's self-forward.
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	if hn, err := os.Hostname(); err == nil {
		hn = strings.ToLower(hn)
		if host == hn || host == strings.SplitN(hn, ".", 2)[0] {
			return true
		}
	}
	lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := lookupHost(lctx, host)
	if err != nil {
		return false
	}
	local := localAddrs()
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if local[ip.String()] {
			return true
		}
	}
	return false
}

func localAddrs() map[string]bool {
	out := make(map[string]bool)
	ifaddrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range ifaddrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && !ip.IsLoopback() {
			out[ip.String()] = true
		}
	}
	return out
}
