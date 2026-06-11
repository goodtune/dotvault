package configsvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/configsvc/store"
)

// maxAdminBodyBytes caps admin request bodies. Layer documents are a few
// KiB; the cap matches the client fetcher's document cap.
const maxAdminBodyBytes = 1 << 20 // 1 MiB

// adminState carries the management surface's runtime: session/CSRF stores,
// the optional password authenticator, and the admin-group requirement. It
// exists only when admin.enabled.
type adminState struct {
	group         string
	sessions      *sessionStore
	csrf          *csrfStore
	authenticator PasswordAuthenticator // nil when ldap login is not configured
	now           func() time.Time
}

// EnableAdmin attaches the management API (and the embedded web UI) to the
// server. Pass a nil authenticator to disable password login (mTLS service
// accounts only).
func (s *Server) EnableAdmin(cfg AdminConfig, authenticator PasswordAuthenticator) {
	s.admin = &adminState{
		group:         cfg.Group,
		sessions:      newSessionStore(cfg.SessionTTL),
		csrf:          newCSRFStore(),
		authenticator: authenticator,
		now:           time.Now,
	}
}

// registerAdminRoutes wires the management API. Every data route goes
// through requireAdmin; CSRF applies to mutating requests authenticated by
// session cookie (certificate-authenticated requests are exempt — they
// carry no ambient browser credential to forge).
func (s *Server) registerAdminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/admin/auth/login", s.handleAdminLogin)
	mux.HandleFunc("POST /v1/admin/auth/logout", s.requireAdmin(s.handleAdminLogout))
	mux.HandleFunc("GET /v1/admin/csrf", s.requireAdmin(s.handleAdminCSRF))
	mux.HandleFunc("GET /v1/admin/whoami", s.requireAdmin(s.handleAdminWhoami))

	mux.HandleFunc("GET /v1/admin/layers", s.requireAdmin(s.handleAdminLayerList))
	mux.HandleFunc("GET /v1/admin/layers/{key...}", s.requireAdmin(s.handleAdminLayerGet))
	mux.HandleFunc("PUT /v1/admin/layers/{key...}", s.requireAdmin(s.handleAdminLayerPut))
	mux.HandleFunc("DELETE /v1/admin/layers/{key...}", s.requireAdmin(s.handleAdminLayerDelete))

	mux.HandleFunc("GET /v1/admin/groups", s.requireAdmin(s.handleAdminGroupsList))
	mux.HandleFunc("GET /v1/admin/groups/{user}", s.requireAdmin(s.handleAdminGroupsGet))
	mux.HandleFunc("PUT /v1/admin/groups/{user}", s.requireAdmin(s.handleAdminGroupsPut))
	mux.HandleFunc("DELETE /v1/admin/groups/{user}", s.requireAdmin(s.handleAdminGroupsDelete))

	mux.HandleFunc("GET /v1/admin/service-accounts", s.requireAdmin(s.handleAdminSAList))
	mux.HandleFunc("GET /v1/admin/service-accounts/{name}", s.requireAdmin(s.handleAdminSAGet))
	mux.HandleFunc("PUT /v1/admin/service-accounts/{name}", s.requireAdmin(s.handleAdminSAPut))
	mux.HandleFunc("DELETE /v1/admin/service-accounts/{name}", s.requireAdmin(s.handleAdminSADelete))

	mux.HandleFunc("GET /v1/admin/preview", s.requireAdmin(s.handleAdminPreview))

	s.registerAdminUI(mux)
}

// identify resolves the request's authenticated identity: a verified client
// certificate (only possible on the mTLS listener, whose TLS config demands
// one) wins, else a session cookie. The boolean reports whether an identity
// was established.
func (s *Server) identify(r *http.Request) (Identity, bool, error) {
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
		// The TLS layer has already verified the chain against the pinned
		// CA, the validity window, and the clientAuth EKU. What remains is
		// the binding to a registered, enabled account: the certificate
		// CN names the service account, and disabling the account revokes
		// access immediately regardless of certificate lifetime.
		name := r.TLS.VerifiedChains[0][0].Subject.CommonName
		if name == "" {
			return Identity{}, false, fmt.Errorf("client certificate has no common name")
		}
		sa, ok, err := s.store.GetServiceAccount(r.Context(), name)
		if err != nil {
			return Identity{}, false, err
		}
		if !ok {
			return Identity{}, false, fmt.Errorf("client certificate CN %q is not a registered service account", name)
		}
		if sa.Disabled {
			return Identity{}, false, fmt.Errorf("service account %q is disabled", name)
		}
		return Identity{Name: name, Kind: identityKindServiceAccount}, true, nil
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return Identity{}, false, nil
	}
	identity, ok := s.admin.sessions.get(cookie.Value)
	return identity, ok, nil
}

// requireAdmin gates a handler on an authenticated admin identity, applying
// CSRF to session-authenticated mutating requests.
func (s *Server) requireAdmin(next func(http.ResponseWriter, *http.Request, Identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity, ok, err := s.identify(r)
		if err != nil {
			slog.Warn("admin: authentication rejected", "path", r.URL.Path, "error", err)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if identity.Kind == identityKindUser && r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !s.admin.csrf.consume(r.Header.Get("X-CSRF-Token")) {
				http.Error(w, "missing or invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		next(w, r, identity)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// audit records an admin mutation with the identity that performed it.
func audit(action string, identity Identity, attrs ...any) {
	attrs = append(attrs, "by", identity.Name, "kind", identity.Kind)
	slog.Info("admin: "+action, attrs...)
}

// --- auth ---

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if s.admin.authenticator == nil {
		http.Error(w, "password login is not configured", http.StatusNotFound)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxAdminBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if !ValidIdentitySegment(strings.TrimSpace(req.Username)) {
		http.Error(w, ErrBadCredentials.Error(), http.StatusUnauthorized)
		return
	}
	username := strings.TrimSpace(req.Username)

	if err := s.admin.authenticator.Authenticate(r.Context(), username, req.Password); err != nil {
		if errors.Is(err, ErrBadCredentials) {
			slog.Info("admin: login failed", "user", username)
			http.Error(w, ErrBadCredentials.Error(), http.StatusUnauthorized)
			return
		}
		slog.Error("admin: login error", "user", username, "error", err)
		http.Error(w, "authentication backend unavailable", http.StatusBadGateway)
		return
	}

	memberOf, err := s.resolver.Groups(r.Context(), username)
	if err != nil {
		slog.Error("admin: group resolution failed during login", "user", username, "error", err)
		http.Error(w, "group resolution failed", http.StatusBadGateway)
		return
	}
	if !contains(memberOf, s.admin.group) {
		slog.Info("admin: login denied, not an admin", "user", username, "required_group", s.admin.group)
		http.Error(w, fmt.Sprintf("membership of group %q is required", s.admin.group), http.StatusForbidden)
		return
	}

	identity := Identity{Name: username, Kind: identityKindUser, Groups: memberOf}
	id := s.admin.sessions.create(identity)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})
	slog.Info("admin: login", "user", username)
	writeJSON(w, http.StatusOK, identity)
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request, identity Identity) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.admin.sessions.delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	slog.Info("admin: logout", "user", identity.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminCSRF(w http.ResponseWriter, r *http.Request, _ Identity) {
	writeJSON(w, http.StatusOK, map[string]string{"token": s.admin.csrf.issue()})
}

func (s *Server) handleAdminWhoami(w http.ResponseWriter, r *http.Request, identity Identity) {
	writeJSON(w, http.StatusOK, identity)
}

// --- layers ---

func (s *Server) handleAdminLayerList(w http.ResponseWriter, r *http.Request, _ Identity) {
	keys, err := s.store.ListLayers(r.Context(), r.URL.Query().Get("prefix"))
	if err != nil {
		slog.Error("admin: list layers failed", "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if keys == nil {
		keys = []string{}
	}
	writeJSON(w, http.StatusOK, map[string][]string{"keys": keys})
}

func (s *Server) handleAdminLayerGet(w http.ResponseWriter, r *http.Request, _ Identity) {
	key := r.PathValue("key")
	doc, ok, err := s.store.GetLayer(r.Context(), key)
	if err != nil {
		slog.Error("admin: get layer failed", "key", key, "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "layer not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Write(doc)
}

func (s *Server) handleAdminLayerPut(w http.ResponseWriter, r *http.Request, identity Identity) {
	key := r.PathValue("key")
	if err := ValidLayerKey(key); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	doc, err := io.ReadAll(io.LimitReader(r.Body, maxAdminBodyBytes+1))
	if err != nil {
		http.Error(w, "read request body", http.StatusBadRequest)
		return
	}
	if len(doc) > maxAdminBodyBytes {
		http.Error(w, "document too large", http.StatusRequestEntityTooLarge)
		return
	}
	// The same validation gate as seed: a layer that cannot ParsePartial +
	// Validate is refused at write time with the validation error in the
	// response, so the UI (and a Terraform provider) surface the problem
	// at plan/apply rather than as a composition 500 later.
	p, err := config.ParsePartial(doc)
	if err == nil {
		err = p.Validate()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.PutLayer(r.Context(), key, doc); err != nil {
		slog.Error("admin: put layer failed", "key", key, "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	audit("put layer", identity, "key", key)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminLayerDelete(w http.ResponseWriter, r *http.Request, identity Identity) {
	key := r.PathValue("key")
	if err := s.store.DeleteLayer(r.Context(), key); err != nil {
		slog.Error("admin: delete layer failed", "key", key, "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	audit("delete layer", identity, "key", key)
	w.WriteHeader(http.StatusNoContent)
}

// --- group membership ---

func (s *Server) handleAdminGroupsList(w http.ResponseWriter, r *http.Request, _ Identity) {
	users, err := s.store.ListGroupUsers(r.Context())
	if err != nil {
		slog.Error("admin: list group users failed", "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if users == nil {
		users = []string{}
	}
	writeJSON(w, http.StatusOK, map[string][]string{"users": users})
}

func (s *Server) handleAdminGroupsGet(w http.ResponseWriter, r *http.Request, _ Identity) {
	user := r.PathValue("user")
	memberOf, ok, err := s.store.GetGroups(r.Context(), user)
	if err != nil {
		slog.Error("admin: get groups failed", "user", user, "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "no membership entry for user", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "groups": memberOf})
}

func (s *Server) handleAdminGroupsPut(w http.ResponseWriter, r *http.Request, identity Identity) {
	user := r.PathValue("user")
	if !ValidIdentitySegment(user) {
		http.Error(w, "invalid username", http.StatusBadRequest)
		return
	}
	var req struct {
		Groups []string `json:"groups"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxAdminBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	for _, g := range req.Groups {
		if !ValidIdentitySegment(g) {
			http.Error(w, fmt.Sprintf("invalid group name %q", g), http.StatusBadRequest)
			return
		}
	}
	if req.Groups == nil {
		req.Groups = []string{}
	}
	if err := s.store.PutGroups(r.Context(), user, req.Groups); err != nil {
		slog.Error("admin: put groups failed", "user", user, "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	audit("put groups", identity, "user", user, "groups", req.Groups)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminGroupsDelete(w http.ResponseWriter, r *http.Request, identity Identity) {
	user := r.PathValue("user")
	if err := s.store.DeleteGroups(r.Context(), user); err != nil {
		slog.Error("admin: delete groups failed", "user", user, "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	audit("delete groups", identity, "user", user)
	w.WriteHeader(http.StatusNoContent)
}

// --- service accounts ---

func (s *Server) handleAdminSAList(w http.ResponseWriter, r *http.Request, _ Identity) {
	names, err := s.store.ListServiceAccounts(r.Context())
	if err != nil {
		slog.Error("admin: list service accounts failed", "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if names == nil {
		names = []string{}
	}
	writeJSON(w, http.StatusOK, map[string][]string{"names": names})
}

func (s *Server) handleAdminSAGet(w http.ResponseWriter, r *http.Request, _ Identity) {
	name := r.PathValue("name")
	sa, ok, err := s.store.GetServiceAccount(r.Context(), name)
	if err != nil {
		slog.Error("admin: get service account failed", "name", name, "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "service account not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, sa)
}

func (s *Server) handleAdminSAPut(w http.ResponseWriter, r *http.Request, identity Identity) {
	name := r.PathValue("name")
	if !ValidIdentitySegment(name) {
		http.Error(w, "invalid service account name", http.StatusBadRequest)
		return
	}
	var req struct {
		Description string `json:"description"`
		Disabled    bool   `json:"disabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxAdminBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	now := s.admin.now().UTC().Truncate(time.Second)
	sa := &store.ServiceAccount{
		Name:        name,
		Description: req.Description,
		Disabled:    req.Disabled,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	// Upsert semantics (Terraform-friendly): an existing account keeps its
	// creation timestamp.
	if existing, ok, err := s.store.GetServiceAccount(r.Context(), name); err != nil {
		slog.Error("admin: get service account failed", "name", name, "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	} else if ok {
		sa.CreatedAt = existing.CreatedAt
	}
	if err := s.store.PutServiceAccount(r.Context(), sa); err != nil {
		slog.Error("admin: put service account failed", "name", name, "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	audit("put service account", identity, "name", name, "disabled", sa.Disabled)
	writeJSON(w, http.StatusOK, sa)
}

func (s *Server) handleAdminSADelete(w http.ResponseWriter, r *http.Request, identity Identity) {
	name := r.PathValue("name")
	if err := s.store.DeleteServiceAccount(r.Context(), name); err != nil {
		slog.Error("admin: delete service account failed", "name", name, "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	audit("delete service account", identity, "name", name)
	w.WriteHeader(http.StatusNoContent)
}

// --- preview ---

// handleAdminPreview composes the document a client identity would receive —
// the `compose` CLI command as an API, for the UI's preview screen and for
// CI assertions. Explicit ?groups= (comma-separated; present-but-empty means
// "no groups") bypasses the resolver.
func (s *Server) handleAdminPreview(w http.ResponseWriter, r *http.Request, _ Identity) {
	q := r.URL.Query()
	osName := strings.TrimSpace(q.Get("os"))
	user := strings.TrimSpace(q.Get("user"))
	if !ValidIdentitySegment(osName) || !ValidIdentitySegment(user) {
		http.Error(w, "os and user query parameters are required and must be valid identity segments", http.StatusBadRequest)
		return
	}

	var memberOf []string
	if q.Has("groups") {
		for _, g := range strings.Split(q.Get("groups"), ",") {
			g = strings.TrimSpace(g)
			if g == "" {
				continue
			}
			if !ValidIdentitySegment(g) {
				http.Error(w, fmt.Sprintf("invalid group name %q", g), http.StatusBadRequest)
				return
			}
			memberOf = append(memberOf, g)
		}
	} else {
		var err error
		memberOf, err = s.resolver.Groups(r.Context(), user)
		if err != nil {
			slog.Error("admin: preview group resolution failed", "user", user, "error", err)
			http.Error(w, "group resolution failed", http.StatusInternalServerError)
			return
		}
	}

	doc, etag, err := s.composer.Compose(r.Context(), LayerKeys(osName, user, memberOf))
	if err != nil {
		var le *LayerError
		if errors.As(err, &le) {
			http.Error(w, fmt.Sprintf("layer %q is invalid", le.Key), http.StatusInternalServerError)
			return
		}
		slog.Error("admin: preview compose failed", "error", err)
		http.Error(w, "compose failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/yaml")
	w.Write(doc)
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
