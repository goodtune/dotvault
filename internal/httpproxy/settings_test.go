package httpproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOverrideFromSettings_HttpsProxyWins(t *testing.T) {
	got, err := OverrideFromSettings(map[string]any{
		"https_proxy": "http://squid.example.com:3128",
		"http_proxy":  "http://other.example.com:8080",
	})
	if err != nil {
		t.Fatalf("OverrideFromSettings: %v", err)
	}
	if got != "http://squid.example.com:3128" {
		t.Errorf("override = %q, want https_proxy value", got)
	}
}

func TestOverrideFromSettings_EmptyHttpsFallsThroughToHttp(t *testing.T) {
	got, err := OverrideFromSettings(map[string]any{
		"https_proxy": "",
		"http_proxy":  "http://other.example.com:8080",
	})
	if err != nil {
		t.Fatalf("OverrideFromSettings: %v", err)
	}
	if got != "http://other.example.com:8080" {
		t.Errorf("override = %q, want http_proxy fallback when https_proxy is empty", got)
	}
}

func TestOverrideFromSettings_NoKeys(t *testing.T) {
	got, err := OverrideFromSettings(map[string]any{
		"client_id": "abc",
	})
	if err != nil {
		t.Fatalf("OverrideFromSettings: %v", err)
	}
	if got != "" {
		t.Errorf("override = %q, want empty when neither key set", got)
	}
}

func TestOverrideFromSettings_NonStringRejected(t *testing.T) {
	if _, err := OverrideFromSettings(map[string]any{"https_proxy": 42}); err == nil {
		t.Error("want error for non-string https_proxy, got nil")
	}
}

func TestClientFromSettings_RoutesThroughOverride(t *testing.T) {
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, r.URL.String())
	}))
	defer proxy.Close()

	client, err := ClientFromSettings(map[string]any{"https_proxy": proxy.URL}, 5*time.Second)
	if err != nil {
		t.Fatalf("ClientFromSettings: %v", err)
	}

	for _, target := range []string{"http://foo.example.com/x", "http://bar.example.com/y"} {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("Get(%s): %v", target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), target) {
			t.Errorf("body %q did not echo target %q", body, target)
		}
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("proxy hits = %d, want 2", got)
	}
}

func TestClientFromSettings_BadOverrideURL(t *testing.T) {
	if _, err := ClientFromSettings(map[string]any{"https_proxy": "://broken"}, time.Second); err == nil {
		t.Error("want error for malformed https_proxy URL, got nil")
	}
}

// TestClientFromSettings_NoOverrideUsesSystemEnv pins down the no-override
// path: with all proxy env vars cleared, the resolver returned by System()
// must yield nil (DIRECT) for an arbitrary target. This is load-bearing —
// a silently-broken System() that returned (someURL, nil) would fail this
// assertion, where the laxer "Proxy != nil" check would not.
//
// Skipped on Windows because System() defers to ieproxy, which falls back
// to the IE/WinHTTP registry settings when the environment is empty —
// those could legitimately point at a corporate proxy on a developer's
// machine, making the nil-DIRECT assertion environment-dependent there.
func TestClientFromSettings_NoOverrideUsesSystemEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("System() reads registry on Windows; nil-DIRECT assertion is host-dependent")
	}

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("https_proxy", "")
	t.Setenv("no_proxy", "")

	client, err := ClientFromSettings(map[string]any{}, time.Second)
	if err != nil {
		t.Fatalf("ClientFromSettings: %v", err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if tr.Proxy == nil {
		t.Fatal("Transport.Proxy is nil; expected System() resolver")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	got, err := tr.Proxy(req)
	if err != nil {
		t.Fatalf("system resolver errored on synthetic request: %v", err)
	}
	if got != nil {
		t.Errorf("system resolver returned %v with no proxy env set, want nil (DIRECT)", got)
	}
}
