package httpproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
		"empty":     "",
		"no scheme": "squid.example.com:3128",
		"no host":   "http://",
		"garbage":   "://%%",
	}
	for name, in := range cases {
		if _, err := Static(in); err == nil {
			t.Errorf("Static(%q): want error, got nil", name)
		}
	}
}

func TestNewClient_RoutesThroughResolver(t *testing.T) {
	// A miniature CONNECT-less proxy that records every request and
	// answers everything with 200 OK. Because the resolver returns this
	// server's URL, both targets in the test should hit it.
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, r.URL.String())
	}))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	resolver := http.ProxyURL(proxyURL)
	client := NewClient(resolver, 5*time.Second)

	for _, target := range []string{"http://foo.example.com/x", "http://bar.example.com/y"} {
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
