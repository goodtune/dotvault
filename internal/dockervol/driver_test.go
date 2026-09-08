package dockervol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
)

func newTestDriver(t *testing.T, store *memStore, events EventSource) (*Driver, string) {
	t.Helper()
	base := t.TempDir()
	d, err := New(Options{
		SocketPath: filepath.Join(base, "docker.sock"),
		VolumeDir:  filepath.Join(base, "volumes"),
		StatePath:  filepath.Join(base, "state.json"),
		DefaultTTL: time.Minute,
		UserPrefix: "users/gary/",
	}, store, events)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, base
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestDriverLifecycle(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	d, base := newTestDriver(t, store, nil)
	ctx := context.Background()

	if err := d.Create("secrets", map[string]string{OptSecrets: "gh"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := d.Create("secrets", map[string]string{OptSecrets: "gh"}); err != nil {
		t.Errorf("re-creating with the same options must be a no-op: %v", err)
	}
	if err := d.Create("secrets", map[string]string{OptSecrets: "jfrog"}); err == nil {
		t.Error("re-creating with different options must be refused")
	}
	if _, err := d.Mount(ctx, "nope", "c1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Mount unknown = %v, want ErrNotFound", err)
	}

	mp, err := d.Mount(ctx, "secrets", "c1")
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if want := filepath.Join(base, "volumes", "secrets"); mp != want {
		t.Errorf("mountpoint = %q, want %q", mp, want)
	}
	if _, err := os.Stat(filepath.Join(mp, "gh.json")); err != nil {
		t.Errorf("volume not populated on mount: %v", err)
	}
	if _, err := d.Mount(ctx, "secrets", "c2"); err != nil {
		t.Fatalf("second Mount: %v", err)
	}
	info, _ := d.Get("secrets")
	if info.Status[StatusMounts] != 2 || info.Status[StatusSecrets] != 1 {
		t.Errorf("status = %v", info.Status)
	}

	if err := d.Unmount("secrets", "c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(mp, "gh.json")); err != nil {
		t.Error("volume wiped while another container still holds it")
	}
	if err := d.Unmount("secrets", "c2"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mp); !errors.Is(err, os.ErrNotExist) {
		t.Error("last unmount must delete the volume directory")
	}
	if err := d.Unmount("secrets", "never-mounted"); err != nil {
		t.Errorf("unmount of an unknown id must be tolerated: %v", err)
	}
	if err := d.Unmount("nope", "x"); err != nil {
		t.Errorf("unmount of an unknown volume must be tolerated: %v", err)
	}
	if p, err := d.Path("secrets"); err != nil || p != mp {
		t.Errorf("Path = %q, %v", p, err)
	}
	if err := d.Remove("secrets"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Get("secrets"); !errors.Is(err, ErrNotFound) {
		t.Error("removed volume still known")
	}
	if len(d.List()) != 0 {
		t.Error("List not empty after remove")
	}
}

func TestMountRefusedWithoutToken(t *testing.T) {
	store := newMemStore()
	d, _ := newTestDriver(t, store, nil)
	hasToken := false
	d.opts.HasToken = func() bool { return hasToken }
	if err := d.Create("v", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Mount(context.Background(), "v", "c1"); !errors.Is(err, ErrNoToken) {
		t.Fatalf("Mount without a token = %v, want ErrNoToken", err)
	}
	hasToken = true
	mp, err := d.Mount(context.Background(), "v", "c1")
	if err != nil {
		t.Fatal(err)
	}
	// A second container joining an already-populated volume does not need
	// Vault at that moment.
	hasToken = false
	if _, err := d.Mount(context.Background(), "v", "c2"); err != nil {
		t.Errorf("second mount refused while the volume is populated: %v", err)
	}
	_ = mp
}

func TestMountFailureLeavesNothingBehind(t *testing.T) {
	store := newMemStore()
	store.setErr(errors.New("vault is sealed"))
	d, _ := newTestDriver(t, store, nil)
	if err := d.Create("v", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Mount(context.Background(), "v", "c1"); err == nil {
		t.Fatal("Mount succeeded against a failing store")
	}
	info, _ := d.Get("v")
	if info.Status[StatusMounts] != 0 {
		t.Error("a failed mount must not count as a mount")
	}
	if info.Status[StatusLastError] == nil {
		t.Error("failure not recorded in status")
	}
}

// Definitions and mount references survive a restart: a new driver over the
// same state resumes the mounted volume in place (a container may still hold
// the directory) and removes the leftovers of an unmounted one.
func TestStatePersistsAndResumes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("resume runs inside Run, which is linux only")
	}
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	d, base := newTestDriver(t, store, nil)
	ctx := context.Background()
	if err := d.Create("held", map[string]string{OptSecrets: "gh"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Create("idle", nil); err != nil {
		t.Fatal(err)
	}
	mp, err := d.Mount(ctx, "held", "c1")
	if err != nil {
		t.Fatal(err)
	}
	// Leftovers an unclean shutdown could leave: a directory for an
	// unmounted volume and one for a volume nobody knows.
	os.MkdirAll(filepath.Join(base, "volumes", "idle"), 0o700)
	os.MkdirAll(filepath.Join(base, "volumes", "forgotten"), 0o700)
	d.stopAll()

	// The secret changed while the daemon was down.
	store.put("gh", map[string]any{"a": "2"})

	d2, err := New(d.opts, store, nil)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- d2.Run(runCtx) }()
	eventually(t, "socket", func() bool { _, err := os.Stat(d.opts.SocketPath); return err == nil })

	info, err := d2.Get("held")
	if err != nil {
		t.Fatalf("held volume forgotten across restart: %v", err)
	}
	if info.Status[StatusMounts] != 1 {
		t.Errorf("mount reference lost across restart: %v", info.Status)
	}
	eventually(t, "resumed volume re-rendered", func() bool {
		b, err := os.ReadFile(filepath.Join(mp, "gh.json"))
		return err == nil && bytes.Contains(b, []byte(`"2"`))
	})
	for _, stale := range []string{"idle", "forgotten"} {
		if _, err := os.Stat(filepath.Join(base, "volumes", stale)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("stale directory %s survived resume", stale)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run: %v", err)
	}
	if _, err := os.Stat(mp); err != nil {
		t.Error("shutdown must leave a mounted volume's directory for the container that holds it")
	}
	if _, err := os.Stat(d.opts.SocketPath); !errors.Is(err, os.ErrNotExist) {
		t.Error("socket not cleaned up on shutdown")
	}
}

func TestCorruptStateIsAnError(t *testing.T) {
	base := t.TempDir()
	statePath := filepath.Join(base, "state.json")
	os.WriteFile(statePath, []byte("{not json"), 0o600)
	_, err := New(Options{SocketPath: "/x", VolumeDir: base, StatePath: statePath, DefaultTTL: time.Minute}, newMemStore(), nil)
	if err == nil {
		t.Fatal("New accepted a corrupt state file; starting empty would make every engine-known volume unmountable silently")
	}
}

// --- protocol -------------------------------------------------------------

func call(t *testing.T, srv *httptest.Server, path string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	resp, err := http.Post(srv.URL+path, contentType, &buf)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if ct := resp.Header.Get("Content-Type"); ct != contentType {
		t.Errorf("%s content-type = %q, want %q", path, ct, contentType)
	}
	return resp.StatusCode, out
}

func TestProtocol(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	d, base := newTestDriver(t, store, nil)
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()

	code, out := call(t, srv, pathActivate, nil)
	if code != 200 || out["Implements"].([]any)[0] != "VolumeDriver" {
		t.Errorf("Activate = %d %v", code, out)
	}
	code, out = call(t, srv, pathCapabilities, map[string]any{})
	if code != 200 || out["Capabilities"].(map[string]any)["Scope"] != "local" {
		t.Errorf("Capabilities = %d %v", code, out)
	}
	code, out = call(t, srv, pathCreate, map[string]any{"Name": "v", "Opts": map[string]string{OptSecrets: "gh"}})
	if code != 200 || out["Err"] != "" {
		t.Errorf("Create = %d %v", code, out)
	}
	code, out = call(t, srv, pathCreate, map[string]any{"Name": "bad", "Opts": map[string]string{"typo": "x"}})
	if code != 500 || out["Err"] == "" {
		t.Errorf("Create with a bad option = %d %v, want a 500 carrying Err", code, out)
	}
	code, out = call(t, srv, pathMount, map[string]any{"Name": "v", "ID": "c1"})
	if code != 200 || out["Mountpoint"] != filepath.Join(base, "volumes", "v") {
		t.Errorf("Mount = %d %v", code, out)
	}
	code, out = call(t, srv, pathPath, map[string]any{"Name": "v"})
	if code != 200 || out["Mountpoint"] == "" {
		t.Errorf("Path = %d %v", code, out)
	}
	code, out = call(t, srv, pathGet, map[string]any{"Name": "v"})
	if code != 200 || out["Volume"].(map[string]any)["Name"] != "v" {
		t.Errorf("Get = %d %v", code, out)
	}
	code, out = call(t, srv, pathGet, map[string]any{"Name": "nope"})
	if code != 404 || out["Err"] == "" {
		t.Errorf("Get unknown = %d %v", code, out)
	}
	code, out = call(t, srv, pathList, nil)
	if code != 200 || len(out["Volumes"].([]any)) != 1 {
		t.Errorf("List = %d %v", code, out)
	}
	code, out = call(t, srv, pathUnmount, map[string]any{"Name": "v", "ID": "c1"})
	if code != 200 || out["Err"] != "" {
		t.Errorf("Unmount = %d %v", code, out)
	}
	code, out = call(t, srv, pathRemove, map[string]any{"Name": "v"})
	if code != 200 || out["Err"] != "" {
		t.Errorf("Remove = %d %v", code, out)
	}
	resp, err := http.Get(srv.URL + pathList)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d, want 405", resp.StatusCode)
	}
}

// --- refresh policy ------------------------------------------------------

func fileHas(path, want string) bool {
	b, err := os.ReadFile(path)
	return err == nil && bytes.Contains(b, []byte(want))
}

// Enterprise: a live subscription drives refreshes and the ticker does not.
func TestEnterpriseRefreshesOnEventsNotTicks(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	store.put("other", map[string]any{"a": "1"})
	events := &fakeEvents{enterprise: true}
	d, _ := newTestDriver(t, store, events)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.setLifetime(ctx)
	go d.runWatcher(ctx)
	eventually(t, "subscription", func() bool { return d.eventsDriving() })

	if err := d.Create("v", map[string]string{OptSecrets: "gh", OptTTL: "20ms"}); err != nil {
		t.Fatal(err)
	}
	mp, err := d.Mount(ctx, "v", "c1")
	if err != nil {
		t.Fatal(err)
	}
	reads0, _ := store.counts()
	time.Sleep(150 * time.Millisecond) // several ticks
	if reads, _ := store.counts(); reads != reads0 {
		t.Errorf("volume was re-read %d times on the ticker while events were live; enterprise caches indefinitely", reads-reads0)
	}

	store.put("gh", map[string]any{"a": "2"})
	events.send(vault.Event{EventType: "kv-v2/data-write", Path: "users/gary/gh"})
	eventually(t, "event-driven refresh", func() bool { return fileHas(filepath.Join(mp, "gh.json"), `"2"`) })

	// An event for a secret the volume does not select is ignored.
	reads1, _ := store.counts()
	events.send(vault.Event{EventType: "kv-v2/data-write", Path: "users/gary/other"})
	events.send(vault.Event{EventType: "kv-v2/data-write", Path: "users/someone-else/gh"})
	time.Sleep(3 * eventDebounce)
	if reads, _ := store.counts(); reads != reads1 {
		t.Errorf("an unrelated event triggered %d reads", reads-reads1)
	}

	// A metadata-delete event names its operation segment differently.
	store.remove("gh")
	events.send(vault.Event{EventType: "kv-v2/metadata-delete", Path: "metadata/users/gary/gh"})
	eventually(t, "deleted secret pruned", func() bool {
		_, err := os.Stat(filepath.Join(mp, "gh.json"))
		return errors.Is(err, os.ErrNotExist)
	})
	info, _ := d.Get("v")
	if info.Status[StatusRefresh] != RefreshEvents {
		t.Errorf("refresh mode = %v, want events", info.Status[StatusRefresh])
	}
}

// Enterprise with the subscription down: the ticker takes over until it
// reconnects, and the reconnect re-renders everything.
func TestEnterpriseFallsBackToPollingWhenSubscriptionDrops(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	events := &fakeEvents{enterprise: true}
	d, _ := newTestDriver(t, store, events)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.setLifetime(ctx)
	go d.runWatcher(ctx)
	eventually(t, "subscription", func() bool { return d.eventsDriving() })

	if err := d.Create("v", map[string]string{OptTTL: "20ms"}); err != nil {
		t.Fatal(err)
	}
	mp, err := d.Mount(ctx, "v", "c1")
	if err != nil {
		t.Fatal(err)
	}

	events.drop(errors.New("websocket closed"))
	eventually(t, "fallback to polling", func() bool { return !d.eventsDriving() })
	if st := d.Status(); st.Refresh != RefreshPoll || st.EventsError == "" {
		t.Errorf("status = %+v, want poll with the error named", st)
	}
	store.put("gh", map[string]any{"a": "2"})
	eventually(t, "poll-driven refresh while disconnected", func() bool { return fileHas(filepath.Join(mp, "gh.json"), `"2"`) })

	// The watcher reconnects after its backoff (1s) and re-renders.
	store.put("gh", map[string]any{"a": "3"})
	eventually(t, "reconnect", func() bool { return events.subscribed() >= 2 && d.eventsDriving() })
	eventually(t, "refresh on reconnect", func() bool { return fileHas(filepath.Join(mp, "gh.json"), `"3"`) })
}

// Community: no subscription is attempted and the ticker drives refreshes.
func TestCommunityPollsOnTTL(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	events := &fakeEvents{enterprise: false}
	d, _ := newTestDriver(t, store, events)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.setLifetime(ctx)
	go d.runWatcher(ctx)
	eventually(t, "edition", func() bool { return d.Status().Refresh == RefreshPoll })

	if err := d.Create("v", map[string]string{OptTTL: "20ms"}); err != nil {
		t.Fatal(err)
	}
	mp, err := d.Mount(ctx, "v", "c1")
	if err != nil {
		t.Fatal(err)
	}
	store.put("gh", map[string]any{"a": "2"})
	eventually(t, "ttl refresh", func() bool { return fileHas(filepath.Join(mp, "gh.json"), `"2"`) })
	if events.subscribed() != 0 {
		t.Error("community edition must not attempt an event subscription")
	}
	if err := d.Unmount("v", "c1"); err != nil {
		t.Fatal(err)
	}
	// The loop is gone with the last mount: no further reads.
	time.Sleep(60 * time.Millisecond)
	reads0, _ := store.counts()
	time.Sleep(60 * time.Millisecond)
	if reads, _ := store.counts(); reads != reads0 {
		t.Error("refresh loop kept running after the last unmount")
	}
}

// The watcher waits for a token before touching Vault, and an edition probe
// that fails is retried rather than assumed.
func TestWatcherWaitsForTokenAndRetriesProbe(t *testing.T) {
	events := &fakeEvents{enterprise: true, healthErr: errors.New("connection refused")}
	d, _ := newTestDriver(t, newMemStore(), events)
	var hasToken atomic.Bool
	d.opts.HasToken = hasToken.Load
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.runWatcher(ctx)

	time.Sleep(50 * time.Millisecond)
	if d.Status().Refresh != RefreshProbing {
		t.Fatalf("refresh mode before a token = %q, want probing", d.Status().Refresh)
	}
	hasToken.Store(true)
	time.Sleep(2*tokenPoll + 100*time.Millisecond)
	if d.Status().Refresh != RefreshProbing {
		t.Fatalf("edition assumed despite the probe failing: %q", d.Status().Refresh)
	}
	events.mu.Lock()
	events.healthErr = nil
	events.mu.Unlock()
	eventually(t, "subscription after the probe recovers", func() bool { return d.eventsDriving() })
}

func TestRelPath(t *testing.T) {
	d, _ := newTestDriver(t, newMemStore(), nil)
	for in, want := range map[string]string{
		"users/gary/gh":              "gh",
		"data/users/gary/a/b":        "a/b",
		"metadata/users/gary/gh":     "gh",
		"destroy/users/gary/gh":      "gh",
		"users/gary/":                "",
		"users/other/gh":             "",
		"apps/x/keys/gary":           "",
		"users/gary/../other/secret": "",
	} {
		got, ok := d.relPath(in)
		if got != want || ok != (want != "") {
			t.Errorf("relPath(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
}
