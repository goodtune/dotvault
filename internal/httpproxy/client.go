package httpproxy

import (
	"net/http"
	"net/url"
	"time"
)

// NewClient builds an *http.Client whose transport routes every
// outbound request through resolver. The transport is cloned from
// http.DefaultTransport so unrelated tuning — TLS handshake timeouts,
// connection pooling, HTTP/2 negotiation — keeps the standard-library
// defaults; only the Proxy field is replaced.
//
// A nil resolver defers to System().
func NewClient(resolver func(*http.Request) (*url.URL, error), timeout time.Duration) *http.Client {
	if resolver == nil {
		resolver = System()
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = resolver
	return &http.Client{Transport: transport, Timeout: timeout}
}
