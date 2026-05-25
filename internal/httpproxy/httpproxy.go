// Package httpproxy resolves the proxy that outbound HTTP requests
// should travel through, and constructs *http.Client instances that
// route through that resolver.
//
// Two resolvers are exposed: System(), which delegates to the host's
// native proxy machinery (Windows IE/WinHTTP settings, including PAC
// scripts; environment variables on Unix); and Static(), which pins
// every request to a single proxy URL supplied by the caller (e.g.
// from a YAML configuration).
//
// Per-request evaluation is preserved by both forms — http.Transport
// invokes the resolver once per outbound request, so a PAC script that
// returns DIRECT for one host and a proxy for another is honoured.
// The Static() resolver is intentionally all-or-nothing: it represents
// the caller's explicit "use this proxy" choice and overrides any
// system-level configuration.
//
// On macOS, native CFNetwork-based proxy detection requires CGO, which
// dotvault avoids for static cross-compiled binaries. System() therefore
// falls back to environment-variable detection on Darwin, matching the
// Linux behaviour. Users who need macOS-native PAC handling can set
// HTTPS_PROXY in the daemon environment or supply a Static() override.
package httpproxy
