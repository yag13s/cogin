package server

import (
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/yag13s/cogin/oidc"
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

func tokenError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// token handles POST /token (authorization_code grant only; there are no
// refresh tokens because relying parties keep their own sessions).
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	client, ok := s.authenticateClient(w, r)
	if !ok {
		return
	}

	// The code is consumed before any check so that a code presented with a
	// wrong verifier cannot be retried.
	ac, err := s.Codes.ConsumeCode(r.Context(), oidc.HashCode(r.PostForm.Get("code")))
	if err != nil {
		log.Printf("consume code: %v", err)
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to read code")
		return
	}
	if err := ac.Redeem(client.ID, r.PostForm.Get("redirect_uri"), r.PostForm.Get("code_verifier")); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "code is invalid, expired or already used")
		return
	}

	now := s.now()
	idToken, err := s.Signer.IDToken(ac, now)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to sign token")
		return
	}
	accessToken, err := s.Signer.AccessToken(ac, now)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "failed to sign token")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(oidc.AccessTokenTTL.Seconds()),
		IDToken:     idToken,
		Scope:       "openid",
	})
}

// authenticateClient accepts client_secret_basic, client_secret_post, or no
// secret for public clients (which must then be registered without one).
func (s *Server) authenticateClient(w http.ResponseWriter, r *http.Request) (*oidc.Client, bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		// RFC 6749 2.3.1: credentials are form-urlencoded before Basic.
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id = r.PostForm.Get("client_id")
		secret = r.PostForm.Get("client_secret")
	}
	client := s.Clients[id]
	if client == nil {
		tokenError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return nil, false
	}
	if client.Confidential() {
		if !client.CheckSecret(secret) {
			tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return nil, false
		}
	} else if secret != "" {
		tokenError(w, http.StatusUnauthorized, "invalid_client", "public client must not send a secret")
		return nil, false
	}
	return client, true
}

// userinfo handles /userinfo with the access token from /token.
func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer`)
		tokenError(w, http.StatusUnauthorized, "invalid_token", "missing bearer token")
		return
	}
	claims, err := s.Signer.VerifyAccessToken(raw)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		tokenError(w, http.StatusUnauthorized, "invalid_token", "invalid access token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":      claims.Subject,
		"name":     claims.Name,
		"card_gen": claims.CardGen,
	})
}
