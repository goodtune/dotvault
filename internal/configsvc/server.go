package configsvc

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/goodtune/dotvault/internal/configsvc/groups"
	"github.com/goodtune/dotvault/internal/configsvc/store"
)

// Server serves the dotvault-config HTTP API. Unlike the daemon's web UI
// there is no loopback-binding invariant and no client auth — this is a
// deployable network service; configuration is not secret, and TLS (the
// operator's ingress or the service's own listener) provides integrity.
type Server struct {
	store       store.Store
	composer    *Composer
	resolver    groups.Resolver
	composition *Composition
	admin       *adminState // nil unless EnableAdmin was called
}

// ServerOption customises a Server.
type ServerOption func(*Server)

// WithComposition replaces the default layer order with an explicit one
// (config: composition.order).
func WithComposition(c *Composition) ServerOption {
	return func(s *Server) {
		if c != nil {
			s.composition = c
		}
	}
}

// NewServer builds a Server over the given backends.
func NewServer(st store.Store, resolver groups.Resolver, opts ...ServerOption) *Server {
	s := &Server{
		store:       st,
		composer:    &Composer{Store: st},
		resolver:    resolver,
		composition: DefaultComposition(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Handler returns the service routes: GET /v1/config (the composed partial
// document), GET /healthz (liveness), GET /readyz (readiness, gated on
// storage Ping), and — when EnableAdmin was called — the /v1/admin API and
// the /admin/ web UI.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/config", s.handleConfig)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	if s.admin != nil {
		s.registerAdminRoutes(mux)
	}
	return mux
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	osName := strings.TrimSpace(r.Header.Get("X-Dotvault-OS"))
	user := strings.TrimSpace(r.Header.Get("X-Dotvault-User"))
	if osName == "" || user == "" {
		http.Error(w, "X-Dotvault-OS and X-Dotvault-User headers are required", http.StatusBadRequest)
		return
	}
	// The device dimension rides the hostname header the client already
	// sends; it is optional (kinds referencing it simply skip when absent),
	// but a present value plays by the same traversal rules as the rest.
	device := strings.TrimSpace(r.Header.Get("X-Dotvault-Hostname"))
	if !ValidIdentitySegment(osName) || !ValidIdentitySegment(user) || (device != "" && !ValidIdentitySegment(device)) {
		http.Error(w, "X-Dotvault-OS, X-Dotvault-User, and X-Dotvault-Hostname must not contain path separators, \"..\", or control characters", http.StatusBadRequest)
		return
	}

	memberOf, err := s.resolver.Groups(ctx, user)
	if err != nil {
		slog.Error("group resolution failed", "user", user, "error", err)
		http.Error(w, "group resolution failed", http.StatusInternalServerError)
		return
	}
	if err := checkResolvedGroups(user, memberOf); err != nil {
		slog.Error("group resolution unusable", "user", user, "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	doc, etag, err := s.composer.Compose(ctx, s.composition.Keys(RequestDims{
		OS:     osName,
		User:   user,
		Device: device,
		Groups: memberOf,
	}))
	if err != nil {
		slog.Error("compose failed", "os", osName, "user", user, "groups", memberOf, "error", err)
		var le *LayerError
		if errors.As(err, &le) {
			// Name the offending layer: layers are non-secret by contract
			// and the operator debugging a 500 needs the key, not a grep
			// through service logs.
			http.Error(w, fmt.Sprintf("layer %q is invalid", le.Key), http.StatusInternalServerError)
			return
		}
		http.Error(w, "compose failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if ifNoneMatchHit(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Write(doc)
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		slog.Warn("readiness probe failed", "error", err)
		http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

// maxCompositionGroups caps how many resolver-returned groups feed
// composition. Every group multiplies the store reads of every
// group-bearing kind in the order, so an over-broad directory filter would
// turn one spoofable-identity request into thousands of backend reads. The
// cap fails loudly (the operator must scope the resolver filter) rather
// than truncating, because serving a silently shrunken composition would be
// wrong config, not degraded service.
const maxCompositionGroups = 64

// checkResolvedGroups validates resolver output before it becomes store-key
// segments: group names come from the operator's store or directory, but an
// LDAP cn is still external input by the time it reaches a Vault path —
// the same traversal rule applies. These are operator-data problems, so the
// callers answer 500, not a client 4xx.
func checkResolvedGroups(user string, memberOf []string) error {
	if len(memberOf) > maxCompositionGroups {
		return fmt.Errorf("user %q resolves to %d groups, above the composition cap of %d — scope the groups resolver filter", user, len(memberOf), maxCompositionGroups)
	}
	for _, g := range memberOf {
		if !ValidIdentitySegment(g) {
			return fmt.Errorf("group %q is not a valid layer key segment", g)
		}
	}
	return nil
}

// ifNoneMatchHit reports whether the If-None-Match header matches the
// current strong ETag. The client (and any well-behaved cache) echoes the
// ETag opaquely; weak-comparison W/ prefixes are accepted because a 304 for
// a byte-identical document is always safe.
func ifNoneMatchHit(header, etag string) bool {
	if header == "" {
		return false
	}
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		candidate = strings.TrimPrefix(candidate, "W/")
		if candidate == etag || candidate == "*" {
			return true
		}
	}
	return false
}
