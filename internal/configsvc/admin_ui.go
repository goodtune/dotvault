package configsvc

import (
	"embed"
	"io/fs"
	"net/http"
)

// adminUI holds the embedded management UI. It is deliberately a
// dependency-free static page (no npm workspace, no build step) — the UI is
// a thin shell over the /v1/admin API, which remains the contract surface
// (the Terraform provider consumes the same routes). If the UI ever
// outgrows this, promote it to a Preact + esbuild workspace like
// internal/web/frontend and extend .github/dependabot.yml accordingly.
//
//go:embed ui
var adminUI embed.FS

// registerAdminUI serves the embedded UI at /admin/. The page itself is
// public (it contains no data); every API call it makes is authenticated.
func (s *Server) registerAdminUI(mux *http.ServeMux) {
	sub, err := fs.Sub(adminUI, "ui")
	if err != nil {
		// The embed is compiled in; a failure here is a build defect.
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	mux.Handle("GET /admin/", http.StripPrefix("/admin/", securityHeaders(fileServer)))
	mux.Handle("GET /admin", http.RedirectHandler("/admin/", http.StatusMovedPermanently))
}

// securityHeaders applies the same posture as the daemon's web UI: a strict
// same-origin CSP and nosniff. The UI is plain same-origin fetch + DOM, so
// 'self' suffices.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
