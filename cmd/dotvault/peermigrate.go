// TODO(pre-1.0, #ISSUE): delete this file. It exists only to move fleets
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/dotvault/internal/peer"
	"github.com/goodtune/dotvault/internal/sshfwd"
)

// remoteSocketTemplateSince is the first release whose sshfwd expands
// {{HOSTNAME}}. A peer reporting an older version is left alone: handing it
// the template would bind a literal-braced socket.
const remoteSocketTemplateSince = "0.34.0"

// legacyRemoteSocket is the pre-0.34 default, the only stored value the
// migration touches. An absolute spelling of the same path is an operator's
// deliberate choice, not the untouched default, so it is left alone.
const legacyRemoteSocket = "~/.ssh/dotvault.sock"

// migrateTimeout bounds the whole background exchange (status, list, csrf,
// patch) so a hung peer cannot leave a goroutine parked for the daemon's
// lifetime.
const migrateTimeout = 15 * time.Second

// peerMigrator PATCHes a workstation's managed-forward entry for this host
// from the old shared default to the per-hostname template, over the very
// socket that forward created. It is daemon-only and runs at most once per
// socket identity per process.
type peerMigrator struct {
	oldDefault string // expanded $HOME/.ssh/dotvault.sock

	mu   sync.Mutex
	done map[peerIdentity]bool
}

// peerIdentity is the device/inode pair behind a socket node. Keying on it
// rather than on the path means a forward that reconnected — a new inode at
// the same path — earns one more attempt, while a failed attempt against the
// socket still sitting there is not retried.
type peerIdentity struct{ dev, ino uint64 }

func newPeerMigrator(oldDefault string) *peerMigrator {
	return &peerMigrator{oldDefault: oldDefault, done: make(map[peerIdentity]bool)}
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
func (m *peerMigrator) maybeMigrate(ctx context.Context, source string) {
	if m == nil || source == "" || source != m.oldDefault {
		return
	}
	id, ok := socketIdentity(source)
	if !ok {
		return
	}
	m.mu.Lock()
	if m.done[id] {
		m.mu.Unlock()
		return
	}
	m.done[id] = true
	m.mu.Unlock()

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
	}
	if err := getJSON(ctx, client, "/api/v1/status", &status); err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if !versionAtLeast(status.Version, remoteSocketTemplateSince) {
		slog.Debug("peer too old for {{HOSTNAME}} forwards; leaving its default socket alone", "socket", socket, "peer_version", status.Version)
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

	for _, r := range list.Remotes {
		if r.RemoteSocket != legacyRemoteSocket || !hostIsSelf(ctx, r.Host) {
			continue
		}
		if err := m.patch(ctx, client, r.Host); err != nil {
			return fmt.Errorf("patch %s: %w", r.Host, err)
		}
	}
	return nil
}

func (m *peerMigrator) patch(ctx context.Context, client *http.Client, host string) error {
	csrf, err := sshCSRFToken(ctx, client, "http://localhost")
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"remote_socket": sshfwd.DefaultRemoteSocket})
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
		// Applying the patch rebinds the forward, which tears down the
		// connection carrying this response. A transport error after the
		// request was written is the expected shape of success; the new
		// socket appearing is the confirmation.
		slog.Info("peer forward migration sent; connection dropped as the forward rebound", "host", host, "socket", sshfwd.DefaultRemoteSocket)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("peer returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	slog.Info("migrated peer forward to the per-hostname socket", "host", host, "socket", sshfwd.DefaultRemoteSocket)
	return nil
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
	addrs, err := net.DefaultResolver.LookupHost(lctx, host)
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
