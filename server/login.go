package server

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/yag13s/cogin/card"
	"github.com/yag13s/cogin/oidc"
)

type loginPage struct {
	ClientName string
	Error      string
}

// authorizePage handles GET /authorize. It validates the request up front so
// a broken client integration fails here, not after the user typed a PIN.
func (s *Server) authorizePage(w http.ResponseWriter, r *http.Request) {
	req, client, err := s.Clients.ParseAuthRequest(r.URL.Query())
	if err != nil {
		var ae *oidc.AuthError
		if errors.As(err, &ae) && ae.Redirectable {
			http.Redirect(w, r, req.ErrorRedirect(ae.Code, ae.Description), http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_ = pages.ExecuteTemplate(w, "error.html", loginPage{Error: "ログインのリクエストが正しくありません。ログインを始めた画面に戻ってやり直してください。"})
		return
	}
	_ = pages.ExecuteTemplate(w, "authorize.html", loginPage{ClientName: client.Name})
}

type authorizeCardRequest struct {
	// Query is the original /authorize query string. Re-validating it here
	// (instead of trusting a server-side session) keeps cogin stateless
	// between the page load and the PIN submit.
	Query  string `json:"query"`
	Token  string `json:"token"`
	PIN    string `json:"pin"`
	NewPIN string `json:"newPin"`
}

type authorizeCardResponse struct {
	Redirect string `json:"redirect"`
}

// authorizeCard handles POST /authorize/card from the login page: it checks
// the scanned card and PIN and returns where to send the browser.
//
// It only accepts JSON, which a cross-site form cannot send without a CORS
// preflight that cogin never approves; that is the CSRF protection.
func (s *Server) authorizeCard(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "JSON required")
		return
	}
	body, ok := decodeJSON[authorizeCardRequest](w, r)
	if !ok {
		return
	}
	q, err := url.ParseQuery(body.Query)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid query")
		return
	}
	req, _, err := s.Clients.ParseAuthRequest(q)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid authorization request")
		return
	}

	c, err := s.Cards.Authenticate(r.Context(), req.ClientID, body.Token, body.PIN, body.NewPIN)
	if err != nil {
		writeCardError(w, err)
		return
	}

	code, hash, err := oidc.NewCode()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to create code")
		return
	}
	ac := &oidc.AuthCode{
		ClientID:      req.ClientID,
		RedirectURI:   req.RedirectURI,
		Subject:       c.Subject,
		Name:          c.DisplayName,
		Generation:    c.Generation,
		CardExpiresAt: c.ExpiresAt,
		Nonce:         req.Nonce,
		CodeChallenge: req.CodeChallenge,
		AuthTime:      s.now().UTC(),
	}
	if err := s.Codes.PutCode(r.Context(), hash, ac, oidc.CodeTTL); err != nil {
		log.Printf("put code: %v", err)
		writeError(w, http.StatusInternalServerError, "server_error", "failed to store code")
		return
	}
	writeJSON(w, http.StatusOK, authorizeCardResponse{Redirect: req.CodeRedirect(code, s.Issuer)})
}

func writeCardError(w http.ResponseWriter, err error) {
	var wrong *card.WrongPINError
	switch {
	case errors.As(err, &wrong):
		rem := wrong.Remaining
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "wrong_pin", Message: "PINが違います", Remaining: &rem})
	case errors.Is(err, card.ErrLocked):
		writeError(w, http.StatusForbidden, "locked", "PINを続けて間違えたため、このカードはロックされました。管理者にカードの再発行を依頼してください")
	case errors.Is(err, card.ErrPINSetupRequired):
		writeError(w, http.StatusUnauthorized, "pin_setup_required", "はじめて使うカードです。PINを決めてください")
	case errors.Is(err, card.ErrPINRequired):
		writeError(w, http.StatusUnauthorized, "pin_required", "PINを入力してください")
	case errors.Is(err, card.ErrWeakPIN):
		writeError(w, http.StatusBadRequest, "weak_pin", "PINは4〜8桁の数字です。1234・1212・2580のような並びや、誕生年のような推測されやすい番号は使えません")
	case errors.Is(err, card.ErrCardExpired):
		writeError(w, http.StatusForbidden, "card_expired", "このカードは有効期限が切れています。必要なら管理者に再発行を依頼してください")
	case errors.Is(err, card.ErrActivationExpired):
		writeError(w, http.StatusForbidden, "activation_expired", "このカードは使い始めの期限が切れています。管理者にカードの再発行を依頼してください")
	case errors.Is(err, card.ErrInvalidCard):
		writeError(w, http.StatusUnauthorized, "invalid_card", "このカードは使えません（無効化されたか、別のサービスのカードです）")
	default:
		log.Printf("card auth: %v", err)
		writeError(w, http.StatusInternalServerError, "server_error", "エラーが発生しました")
	}
}

// cardLanding handles GET /c, the URL printed in the QR code. The token is in
// the fragment, so it never reaches cogin's (or a CDN's) access logs; the
// page's script reads it and continues with POST /card/resolve.
func (s *Server) cardLanding(w http.ResponseWriter, _ *http.Request) {
	_ = pages.ExecuteTemplate(w, "card.html", loginPage{})
}

type resolveRequest struct {
	Token string `json:"token"`
}

type resolveResponse struct {
	ClientName       string `json:"clientName"`
	InitiateLoginURI string `json:"initiateLoginUri,omitempty"`
}

// resolveCard handles POST /card/resolve: for a card scanned outside a login
// (phone camera), it tells the page which service to start the login at.
func (s *Server) resolveCard(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "JSON required")
		return
	}
	body, ok := decodeJSON[resolveRequest](w, r)
	if !ok {
		return
	}
	c, err := s.Cards.Resolve(r.Context(), body.Token)
	if err != nil {
		writeCardError(w, err)
		return
	}
	client := s.Clients[c.ClientID]
	if client == nil {
		writeError(w, http.StatusUnauthorized, "invalid_card", "このカードは使えません")
		return
	}
	resp := resolveResponse{ClientName: client.Name}
	if client.InitiateLoginURI != "" {
		u, err := url.Parse(client.InitiateLoginURI)
		if err == nil {
			qs := u.Query()
			qs.Set("iss", s.Issuer)
			u.RawQuery = qs.Encode()
			resp.InitiateLoginURI = u.String()
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
