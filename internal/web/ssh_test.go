package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/goodtune/dotvault/internal/sshfwd"
)

// fixedVerifier is a minimal sshfwd.Verifier for these handler tests: it
// always returns the same VerifyResult/error it was constructed with,
// regardless of the Remote it's asked about. sshfwd's own registry_test.go
// has a richer family of fakes, but those are unexported there — this
// package needs its own copy of the one shape these tests use.
type fixedVerifier struct {
	result sshfwd.VerifyResult
	err    error
}

func (f fixedVerifier) Verify(ctx context.Context, r sshfwd.Remote, opts sshfwd.VerifyOptions) (sshfwd.VerifyResult, error) {
	return f.result, f.err
}

// noopVerifier reports every host as verified with nothing new to confirm
// (Verified: true, no HostKey/Fingerprint) — the shape Add treats as
// "CA-covered, nothing to pin", so it commits an Add immediately with no
// confirmation round trip. Used wherever a test just needs a remote to exist
// and does not care about the host-key handshake.
var noopVerifier = fixedVerifier{result: sshfwd.VerifyResult{Verified: true}}

// testHostKey generates a fresh, self-consistent (authorized-key,
// SHA256-fingerprint) pair. Add independently re-derives a reported key's
// fingerprint and refuses to pin if the two disagree, so a VerifyResult
// carrying a HostKey needs a real, matching Fingerprint — a placeholder
// string does not parse.
func testHostKey(t *testing.T) (key, fingerprint string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub)), ssh.FingerprintSHA256(sshPub)
}

// newSSHRegistry returns a Registry backed by a fresh ssh.yaml under a
// temporary directory, with a Manager whose reconcile goroutines are
// stopped at cleanup. The zero-value Deps means any remote Reconcile
// actually starts spins its connect loop failing fast on missing
// Signers/User/Policy/Target rather than making a live network call —
// harmless here, since these tests only exercise the Registry's
// file-mutation and confirmation-gate behaviour, not real connections.
func newSSHRegistry(t *testing.T, v sshfwd.Verifier) *sshfwd.Registry {
	t.Helper()
	mgr := sshfwd.NewManager(sshfwd.Deps{})
	t.Cleanup(mgr.Close)
	path := filepath.Join(t.TempDir(), "ssh.yaml")
	return sshfwd.NewRegistry(path, mgr, v)
}

// sshTestServer builds a Server with the SSH CRUD routes registered and its
// Registry backed by a fresh, isolated ssh.yaml.
func sshTestServer(t *testing.T, v sshfwd.Verifier) *Server {
	t.Helper()
	s := testServer(t)
	s.sshRegistry = newSSHRegistry(t, v)
	s.registerRoutes()
	return s
}

func jsonBody(t *testing.T, v any) *strings.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return strings.NewReader(string(b))
}

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("body is not valid JSON: %v (body = %s)", err, w.Body.String())
	}
	return out
}

func TestSSHRemotesListEmpty(t *testing.T) {
	s := sshTestServer(t, noopVerifier)

	req := httptest.NewRequest("GET", "/api/v1/ssh/remotes", nil)
	w := httptest.NewRecorder()
	s.handleSSHList(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON(t, w)
	remotes, ok := resp["remotes"].([]any)
	if !ok {
		t.Fatalf("remotes is %T, want []any", resp["remotes"])
	}
	if len(remotes) != 0 {
		t.Errorf("len(remotes) = %d, want 0", len(remotes))
	}
}

func TestSSHRemotesAddReturns409WithFingerprint(t *testing.T) {
	key, fp := testHostKey(t)
	v := fixedVerifier{result: sshfwd.VerifyResult{Verified: true, HostKey: key, Fingerprint: fp}}
	s := sshTestServer(t, v)

	req := httptest.NewRequest("POST", "/api/v1/ssh/remotes", jsonBody(t, map[string]any{"host": "example.com"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleSSHAdd(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON(t, w)
	if resp["host"] != "example.com" {
		t.Errorf("host = %v, want %q", resp["host"], "example.com")
	}
	if resp["fingerprint"] != fp {
		t.Errorf("fingerprint = %v, want %q", resp["fingerprint"], fp)
	}

	// Nothing was persisted: a 409 is a request for confirmation, not a
	// partial write.
	remotes, err := s.sshRegistry.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remotes) != 0 {
		t.Errorf("List() = %v, want empty (unconfirmed Add must not persist)", remotes)
	}
}

func TestSSHRemotesAddCommitsWithFingerprint(t *testing.T) {
	key, fp := testHostKey(t)
	v := fixedVerifier{result: sshfwd.VerifyResult{Verified: true, HostKey: key, Fingerprint: fp}}
	s := sshTestServer(t, v)

	// First POST: unconfirmed, gets the 409.
	req := httptest.NewRequest("POST", "/api/v1/ssh/remotes", jsonBody(t, map[string]any{"host": "example.com"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleSSHAdd(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("first POST status = %d, want 409; body = %s", w.Code, w.Body.String())
	}

	// Re-POST echoing the fingerprint back commits it.
	req = httptest.NewRequest("POST", "/api/v1/ssh/remotes", jsonBody(t, map[string]any{
		"host":               "example.com",
		"accept_fingerprint": fp,
	}))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.handleSSHAdd(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("second POST status = %d, want 201; body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON(t, w)
	if resp["host"] != "example.com" {
		t.Errorf("host = %v, want %q", resp["host"], "example.com")
	}

	remotes, err := s.sshRegistry.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remotes) != 1 || remotes[0].Host != "example.com" {
		t.Errorf("List() = %v, want one remote for example.com", remotes)
	}
}

// The three CSRF tests below dispatch through the real mux (s.mux.ServeHTTP)
// rather than calling s.requireCSRF(s.handleSSHX) directly, so a regression
// in server.go's route registration — the wrapper accidentally dropped from
// a route — fails these tests. Calling the wrapper by hand would instead
// only prove requireCSRF itself works, which csrf_test.go already covers.

func TestSSHRemotesAddRequiresCSRF(t *testing.T) {
	s := sshTestServer(t, noopVerifier)

	req := httptest.NewRequest("POST", "/api/v1/ssh/remotes", jsonBody(t, map[string]any{"host": "example.com"}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for missing CSRF; body = %s", w.Code, w.Body.String())
	}

	// The load-bearing assertion: no remote was actually added.
	remotes, err := s.sshRegistry.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remotes) != 0 {
		t.Errorf("List() = %v, want empty — the CSRF-rejected Add must not have persisted", remotes)
	}
}

func TestSSHRemotesPatchRequiresCSRF(t *testing.T) {
	s := sshTestServer(t, noopVerifier)
	if _, err := s.sshRegistry.Add(context.Background(), sshfwd.Remote{Host: "example.com"}, sshfwd.AddOptions{}); err != nil {
		t.Fatalf("seeding Add: %v", err)
	}

	req := httptest.NewRequest("PATCH", "/api/v1/ssh/remotes/example.com", jsonBody(t, map[string]any{"enabled": false}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for missing CSRF; body = %s", w.Code, w.Body.String())
	}

	remotes, err := s.sshRegistry.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remotes) != 1 || !remotes[0].EnabledOrDefault() {
		t.Errorf("List() = %v, want the seeded remote untouched (still enabled)", remotes)
	}
}

func TestSSHRemotesDeleteRequiresCSRF(t *testing.T) {
	s := sshTestServer(t, noopVerifier)
	if _, err := s.sshRegistry.Add(context.Background(), sshfwd.Remote{Host: "example.com"}, sshfwd.AddOptions{}); err != nil {
		t.Fatalf("seeding Add: %v", err)
	}

	req := httptest.NewRequest("DELETE", "/api/v1/ssh/remotes/example.com", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for missing CSRF; body = %s", w.Code, w.Body.String())
	}

	remotes, err := s.sshRegistry.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remotes) != 1 {
		t.Errorf("List() = %v, want the seeded remote still present", remotes)
	}
}

func TestSSHRemotesDeleteUnknownHost(t *testing.T) {
	s := sshTestServer(t, noopVerifier)

	req := httptest.NewRequest("DELETE", "/api/v1/ssh/remotes/nope.example.com", nil)
	req.SetPathValue("host", "nope.example.com")
	w := httptest.NewRecorder()
	s.handleSSHDelete(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", w.Code, w.Body.String())
	}
}

func TestSSHRemotesPatchUnknownHost(t *testing.T) {
	// The sibling of TestSSHRemotesDeleteUnknownHost: PATCH on a host with
	// no configured entry must also be 404, distinguishable from a
	// malformed patch body (400) via sshfwd.ErrHostNotFound.
	s := sshTestServer(t, noopVerifier)

	req := httptest.NewRequest("PATCH", "/api/v1/ssh/remotes/nope.example.com", jsonBody(t, map[string]any{"enabled": false}))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("host", "nope.example.com")
	w := httptest.NewRecorder()
	s.handleSSHPatch(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", w.Code, w.Body.String())
	}
}

func TestSSHRemotesAddOversizeBody(t *testing.T) {
	// A body past sshBodyLimit must produce a 400 via MaxBytesReader, not a
	// hang, a success, or an unbounded allocation.
	s := sshTestServer(t, noopVerifier)

	big := `{"host":"` + strings.Repeat("a", sshBodyLimit+1) + `"}`
	req := httptest.NewRequest("POST", "/api/v1/ssh/remotes", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleSSHAdd(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an oversize body; body = %s", w.Code, w.Body.String())
	}

	remotes, err := s.sshRegistry.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remotes) != 0 {
		t.Errorf("List() = %v, want empty — an oversize body must not persist anything", remotes)
	}
}

func TestSSHRemotesHostPathValueRejectsUnsafeShapes(t *testing.T) {
	// {host} arrives from a mux wildcard, unescaped — a value that only
	// PathValue's decoding produces (an embedded "/", a NUL byte) or a
	// leading "-" (an ssh(1) option-injection vector) must never reach
	// Registry. Exercised against both PATCH and DELETE, the two handlers
	// that take host from the URL path rather than a validated request body.
	cases := []struct {
		name string
		host string
	}{
		{"embedded slash from %2F", "foo/bar"},
		{"embedded NUL from %00", "foo\x00bar"},
		{"leading dash", "-oProxyCommand=x"},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/PATCH", func(t *testing.T) {
			s := sshTestServer(t, noopVerifier)
			if _, err := s.sshRegistry.Add(context.Background(), sshfwd.Remote{Host: "example.com"}, sshfwd.AddOptions{}); err != nil {
				t.Fatalf("seeding Add: %v", err)
			}

			req := httptest.NewRequest("PATCH", "/api/v1/ssh/remotes/x", jsonBody(t, map[string]any{"enabled": false}))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("host", tc.host)
			w := httptest.NewRecorder()
			s.handleSSHPatch(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body = %s", w.Code, w.Body.String())
			}
			remotes, err := s.sshRegistry.List()
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(remotes) != 1 || !remotes[0].EnabledOrDefault() {
				t.Errorf("List() = %v, want the seeded remote untouched", remotes)
			}
		})

		t.Run(tc.name+"/DELETE", func(t *testing.T) {
			s := sshTestServer(t, noopVerifier)
			if _, err := s.sshRegistry.Add(context.Background(), sshfwd.Remote{Host: "example.com"}, sshfwd.AddOptions{}); err != nil {
				t.Fatalf("seeding Add: %v", err)
			}

			req := httptest.NewRequest("DELETE", "/api/v1/ssh/remotes/x", nil)
			req.SetPathValue("host", tc.host)
			w := httptest.NewRecorder()
			s.handleSSHDelete(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body = %s", w.Code, w.Body.String())
			}
			remotes, err := s.sshRegistry.List()
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(remotes) != 1 {
				t.Errorf("List() = %v, want the seeded remote still present", remotes)
			}
		})
	}
}

func TestSSHEndpointsDisabledWithoutRegistry(t *testing.T) {
	s := testServer(t) // sshRegistry left nil

	cases := []struct {
		name string
		call func() *httptest.ResponseRecorder
	}{
		{"list", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			s.handleSSHList(w, httptest.NewRequest("GET", "/api/v1/ssh/remotes", nil))
			return w
		}},
		{"add", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/api/v1/ssh/remotes", jsonBody(t, map[string]any{"host": "x"}))
			s.handleSSHAdd(w, req)
			return w
		}},
		{"patch", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("PATCH", "/api/v1/ssh/remotes/x", jsonBody(t, map[string]any{}))
			req.SetPathValue("host", "x")
			s.handleSSHPatch(w, req)
			return w
		}},
		{"delete", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("DELETE", "/api/v1/ssh/remotes/x", nil)
			req.SetPathValue("host", "x")
			s.handleSSHDelete(w, req)
			return w
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.call()
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503; body = %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestStatusIncludesSSHBlock(t *testing.T) {
	s := testServer(t)
	s.sshStatus = func() []sshfwd.RemoteStatus {
		return []sshfwd.RemoteStatus{{Host: "example.com", State: "connected"}}
	}

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	s.handleStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}
	resp := decodeJSON(t, w)
	sshBlock, ok := resp["ssh"].([]any)
	if !ok {
		t.Fatalf("ssh block is %T, want []any; body = %s", resp["ssh"], w.Body.String())
	}
	if len(sshBlock) != 1 {
		t.Fatalf("len(ssh) = %d, want 1", len(sshBlock))
	}
	entry, ok := sshBlock[0].(map[string]any)
	if !ok || entry["host"] != "example.com" {
		t.Errorf("ssh[0] = %v, want host=example.com", sshBlock[0])
	}
}
