// Package server is cogin's HTTP layer: the OpenID Connect endpoints, the
// hosted card login page and the card management API.
package server

import (
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/yag13s/cogin/card"
	"github.com/yag13s/cogin/oidc"
)

//go:embed web
var webFS embed.FS

var pages = template.Must(template.ParseFS(webFS, "web/*.html"))

// Server wires cogin's dependencies into an http.Handler.
type Server struct {
	Issuer  string
	Clients oidc.Clients
	Cards   *card.Service
	Codes   oidc.CodeStore
	Signer  *oidc.Signer
	Now     func() time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler returns the router.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(transportHeaders)
	// HEAD is answered by the GET handler (scanners and uptime checks use it).
	r.Use(middleware.GetHead)

	// Endpoints used by relying parties from browsers (public clients) carry
	// no cookies and no ambient authority, so they can be open to any origin.
	// Preflight is registered per path: a catch-all OPTIONS route would turn
	// every unknown path into 405 instead of 404.
	preflight := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
	r.Group(func(r chi.Router) {
		r.Use(openCORS)
		r.Get("/.well-known/openid-configuration", s.discovery)
		r.Get("/jwks.json", s.jwks)
		r.Post("/token", s.token)
		r.Get("/userinfo", s.userinfo)
		r.Post("/userinfo", s.userinfo)
		for _, p := range []string{"/.well-known/openid-configuration", "/jwks.json", "/token", "/userinfo"} {
			r.Options(p, preflight)
		}
	})

	// The login pages are same-origin only.
	r.Group(func(r chi.Router) {
		r.Use(pageHeaders)
		r.Get("/", s.home)
		r.Get("/authorize", s.authorizePage)
		r.Post("/authorize/card", s.authorizeCard)
		r.Get("/c", s.cardLanding)
		r.Post("/card/resolve", s.resolveCard)
		static, _ := fs.Sub(webFS, "web/static")
		r.Handle("/static/*", http.StripPrefix("/static/", http.FileServerFS(static)))
	})

	r.Route("/admin/v1", func(r chi.Router) {
		r.Use(noStore)
		r.Get("/cards", s.adminListCards)
		r.Post("/cards/issue", s.adminIssue)
		r.Post("/cards/revoke", s.adminRevoke)
		r.Post("/cards/unlock", s.adminUnlock)
	})

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	return r
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         s.Issuer,
		"authorization_endpoint":                         s.Issuer + "/authorize",
		"token_endpoint":                                 s.Issuer + "/token",
		"userinfo_endpoint":                              s.Issuer + "/userinfo",
		"jwks_uri":                                       s.Issuer + "/jwks.json",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"ES256"},
		"scopes_supported":                               []string{"openid", "profile"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":               []string{"S256"},
		"claims_supported":                               []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "amr", "name", "card_gen", "card_exp"},
		"authorization_response_iss_parameter_supported": true,
	})
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/jwk-set+json")
	_, _ = w.Write(s.Signer.JWKS())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// apiError is the error body of cogin's own JSON APIs (login page, admin).
type apiError struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	Remaining *int   `json:"remaining,omitempty"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, apiError{Error: code, Message: message})
}

// decodeJSON reads a small JSON body. The size cap keeps unauthenticated
// endpoints from buffering arbitrary input.
func decodeJSON[T any](w http.ResponseWriter, r *http.Request) (*T, bool) {
	var v T
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return nil, false
	}
	return &v, true
}

func openCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		next.ServeHTTP(w, r)
	})
}

// pageHeaders locks the login pages down: no framing (clickjacking a PIN
// prompt), no inline script, no referrer (the URL may carry state).
func pageHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(self)")
		if r.URL.Path != "" && len(r.URL.Path) > 8 && r.URL.Path[:8] == "/static/" {
			h.Set("Cache-Control", "public, max-age=300")
		} else {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// transportHeaders apply to every response, API and pages alike.
func transportHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// cogin is only ever served over HTTPS (API Gateway custom domain).
		// No includeSubDomains: sibling hosts of the issuer may not be ours to pin.
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// home handles GET /: a plain page so the bare domain does not look broken.
func (s *Server) home(w http.ResponseWriter, _ *http.Request) {
	_ = pages.ExecuteTemplate(w, "home.html", loginPage{})
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
