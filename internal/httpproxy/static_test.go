package httpproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStatic_PinsAllRequests(t *testing.T) {
	resolver, err := Static("http://squid.example.com:3128")
	if err != nil {
		t.Fatalf("Static: %v", err)
	}

	cases := []string{
		"https://api.github.com/user",
		"https://github.com/login/device/code",
		"https://example.org/anything",
	}
	for _, target := range cases {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatalf("NewRequest(%s): %v", target, err)
		}
		got, err := resolver(req)
		if err != nil {
			t.Fatalf("resolver(%s): %v", target, err)
		}
		if got == nil {
			t.Fatalf("resolver(%s) = nil, want squid URL", target)
		}
		if got.Host != "squid.example.com:3128" {
			t.Errorf("resolver(%s) host = %q, want %q", target, got.Host, "squid.example.com:3128")
		}
	}
}

func TestStatic_RejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"scheme only":        "http://",
		"schemeless host":    "squid.example.com:3128",
		"schemeless //auth":  "//squid.example.com:3128",
		"garbage":            "://%%",
		"unsupported scheme": "ftp://squid.example.com:3128",
		"javascript scheme":  "javascript://x:1",
	}
	for name, in := range cases {
		if _, err := Static(in); err == nil {
			t.Errorf("Static(%q): want error, got nil", name)
		}
	}
}

func TestStatic_ErrorDoesNotLeakUserinfoPassword(t *testing.T) {
	// Force the "missing host" branch by giving a userinfo block with
	// no authority host. The error wraps the URL — it must not surface
	// the password.
	_, err := Static("http://alice:hunter2@/")
	if err == nil {
		t.Fatal("Static: want error, got nil")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error %q leaks password", err.Error())
	}
}

func TestNewClient_RoutesThroughResolver(t *testing.T) {
	// A miniature CONNECT-less proxy that records every request and
	// answers with 200 OK. Because the resolver returns this server's
	// URL, both targets in the test should hit it.
	var (
		hits  atomic.Int32
		mu    sync.Mutex
		seen  []string
	)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		mu.Lock()
		seen = append(seen, r.URL.String())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, r.URL.String())
	}))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	client := NewClient(http.ProxyURL(proxyURL), 5*time.Second)

	targets := []string{"http://foo.example.com/x", "http://bar.example.com/y"}
	for _, target := range targets {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("Get(%s): %v", target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// http.Transport forwards absolute URLs to the proxy.
		if !strings.Contains(string(body), target) {
			t.Errorf("proxy received %q, want body to contain %q", string(body), target)
		}
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("proxy hits = %d, want 2", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != len(targets) {
		t.Fatalf("proxy saw %d requests, want %d", len(seen), len(targets))
	}
	for i, want := range targets {
		if seen[i] != want {
			t.Errorf("proxy saw %q at %d, want %q", seen[i], i, want)
		}
	}
}

func TestNewClient_NilResolverFallsBackToSystem(t *testing.T) {
	c := NewClient(nil, 0)
	if c.Transport == nil {
		t.Fatal("Transport is nil")
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", c.Transport)
	}
	if tr.Proxy == nil {
		t.Fatal("Transport.Proxy is nil; nil resolver should default to System()")
	}
}
