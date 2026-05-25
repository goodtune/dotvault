package enrol

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEngineProxyOverride_HttpsProxyWins(t *testing.T) {
	got, err := engineProxyOverride(map[string]any{
		"https_proxy": "http://squid.example.com:3128",
		"http_proxy":  "http://other.example.com:8080",
	})
	if err != nil {
		t.Fatalf("engineProxyOverride: %v", err)
	}
	if got != "http://squid.example.com:3128" {
		t.Errorf("override = %q, want https_proxy value", got)
	}
}

func TestEngineProxyOverride_FallsThroughEmpty(t *testing.T) {
	got, err := engineProxyOverride(map[string]any{
		"https_proxy": "",
		"http_proxy":  "http://other.example.com:8080",
	})
	if err != nil {
		t.Fatalf("engineProxyOverride: %v", err)
	}
	if got != "http://other.example.com:8080" {
		t.Errorf("override = %q, want http_proxy fallback when https_proxy is empty", got)
	}
}

func TestEngineProxyOverride_NoKeys(t *testing.T) {
	got, err := engineProxyOverride(map[string]any{
		"client_id": "abc",
	})
	if err != nil {
		t.Fatalf("engineProxyOverride: %v", err)
	}
	if got != "" {
		t.Errorf("override = %q, want empty when neither key set", got)
	}
}

func TestEngineProxyOverride_NonStringRejected(t *testing.T) {
	if _, err := engineProxyOverride(map[string]any{"https_proxy": 42}); err == nil {
		t.Error("want error for non-string https_proxy, got nil")
	}
}

func TestEngineHTTPClient_RoutesThroughOverride(t *testing.T) {
	var hits atomic.Int32
	var seenHosts []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		seenHosts = append(seenHosts, r.URL.Host)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, r.URL.String())
	}))
	defer proxy.Close()

	client, err := engineHTTPClient(map[string]any{"https_proxy": proxy.URL}, 5*time.Second)
	if err != nil {
		t.Fatalf("engineHTTPClient: %v", err)
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

func TestEngineHTTPClient_BadOverrideURL(t *testing.T) {
	if _, err := engineHTTPClient(map[string]any{"https_proxy": "://broken"}, time.Second); err == nil {
		t.Error("want error for malformed https_proxy URL, got nil")
	}
}

func TestEngineHTTPClient_NoOverrideUsesSystem(t *testing.T) {
	client, err := engineHTTPClient(map[string]any{}, time.Second)
	if err != nil {
		t.Fatalf("engineHTTPClient: %v", err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if tr.Proxy == nil {
		t.Fatal("Transport.Proxy is nil; expected System() resolver")
	}
	// A bare GET to an arbitrary URL should not be intercepted by a static
	// proxy, which would surface as a non-nil URL here. We don't enforce
	// nil (CI may carry HTTPS_PROXY) — we just sanity-check the resolver
	// returns without erroring on a synthetic request.
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if _, err := tr.Proxy(req); err != nil {
		t.Errorf("system resolver errored on synthetic request: %v", err)
	}
}
