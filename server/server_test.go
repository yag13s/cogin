package server_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yag13s/cogin/card"
	"github.com/yag13s/cogin/oidc"
	"github.com/yag13s/cogin/server"
	"github.com/yag13s/cogin/store/memstore"
)

const (
	clientSecret = "s3cret"
	adminKey     = "myapp.admin-key"
	redirectURI  = "https://rp.example/callback"
	verifier     = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-extra"
)

type env struct {
	t      *testing.T
	ts     *httptest.Server
	signer *oidc.Signer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	store := memstore.New()
	cards, err := card.NewService(store, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := oidc.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := &server.Server{
		Clients: oidc.Clients{
			"myapp": {
				ID: "myapp", Name: "My App",
				RedirectURIs:     []string{redirectURI},
				SecretHash:       oidc.HashSecret(clientSecret),
				AdminKeyHash:     oidc.HashSecret(adminKey),
				InitiateLoginURI: "https://rp.example/login/card",
			},
			"other": {ID: "other", Name: "Other", RedirectURIs: []string{"https://other.example/cb"}},
		},
		Cards: cards,
		Codes: store,
	}
	ts := httptest.NewServer(nil)
	srv.Issuer = ts.URL
	srv.Signer, err = oidc.NewSigner(ts.URL, key)
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = srv.Handler()
	t.Cleanup(ts.Close)
	return &env{t: t, ts: ts, signer: srv.Signer}
}

func (e *env) do(method, path, auth, contentType, body string) (*http.Response, map[string]any) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.ts.URL+path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

func (e *env) issue(subject string) string {
	e.t.Helper()
	res, out := e.do("POST", "/admin/v1/cards/issue", "Bearer "+adminKey, "application/json", `{"subject":"`+subject+`","displayName":"たろう"}`)
	if res.StatusCode != 200 {
		e.t.Fatalf("issue: %d %v", res.StatusCode, out)
	}
	if !strings.HasPrefix(out["cardUrl"].(string), e.ts.URL+"/c#cgc_") || out["qrPng"] == "" {
		e.t.Fatalf("issue response = %v", out)
	}
	return out["token"].(string)
}

func challenge() string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func authQuery() string {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"myapp"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid"},
		"state":                 {"st"},
		"nonce":                 {"n0"},
		"code_challenge":        {challenge()},
		"code_challenge_method": {"S256"},
	}.Encode()
}

func (e *env) login(token, pin, newPin string) (*http.Response, map[string]any) {
	body, _ := json.Marshal(map[string]string{"query": authQuery(), "token": token, "pin": pin, "newPin": newPin})
	return e.do("POST", "/authorize/card", "", "application/json", string(body))
}

func (e *env) codeFrom(redirect string) string {
	e.t.Helper()
	u, err := url.Parse(redirect)
	if err != nil || !strings.HasPrefix(redirect, redirectURI+"?") {
		e.t.Fatalf("redirect = %q", redirect)
	}
	if u.Query().Get("state") != "st" || u.Query().Get("iss") != e.ts.URL {
		e.t.Fatalf("redirect params = %v", u.Query())
	}
	return u.Query().Get("code")
}

func (e *env) exchange(code, verif string) (*http.Response, map[string]any) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verif},
	}
	req, _ := http.NewRequest("POST", e.ts.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("myapp", clientSecret)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

func TestFullLoginFlow(t *testing.T) {
	e := newEnv(t)

	res, _ := e.do("GET", "/authorize?"+authQuery(), "", "", "")
	if res.StatusCode != 200 || res.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("authorize page: %d %v", res.StatusCode, res.Header)
	}

	token := e.issue("abc/guest:1")

	res, out := e.login(token, "", "")
	if res.StatusCode != 401 || out["error"] != "pin_setup_required" {
		t.Fatalf("first login = %d %v", res.StatusCode, out)
	}
	res, out = e.login(token, "", "3947")
	if res.StatusCode != 200 {
		t.Fatalf("setup login = %d %v", res.StatusCode, out)
	}
	code := e.codeFrom(out["redirect"].(string))

	res, tok := e.exchange(code, verifier)
	if res.StatusCode != 200 {
		t.Fatalf("token = %d %v", res.StatusCode, tok)
	}

	// Verify the ID token the way a relying party would: with the JWKS only.
	var claims oidc.IDTokenClaims
	_, err := jwt.ParseWithClaims(tok["id_token"].(string), &claims, func(*jwt.Token) (any, error) {
		return jwksKey(t, e), nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(e.ts.URL), jwt.WithAudience("myapp"))
	if err != nil {
		t.Fatalf("id token: %v", err)
	}
	if claims.Subject != "abc/guest:1" || claims.Nonce != "n0" || claims.CardGeneration != 1 || claims.Name != "たろう" {
		t.Fatalf("claims = %+v", claims)
	}

	res, info := e.do("GET", "/userinfo", "Bearer "+tok["access_token"].(string), "", "")
	if res.StatusCode != 200 || info["sub"] != "abc/guest:1" {
		t.Fatalf("userinfo = %d %v", res.StatusCode, info)
	}
	// An ID token is not an access token.
	if res, _ := e.do("GET", "/userinfo", "Bearer "+tok["id_token"].(string), "", ""); res.StatusCode != 401 {
		t.Fatalf("userinfo with id token = %d", res.StatusCode)
	}

	// Codes are single use.
	if res, out := e.exchange(code, verifier); res.StatusCode != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("code reuse = %d %v", res.StatusCode, out)
	}
}

func TestWrongVerifierBurnsCode(t *testing.T) {
	e := newEnv(t)
	token := e.issue("u")
	_, out := e.login(token, "", "3947")
	code := e.codeFrom(out["redirect"].(string))
	if res, _ := e.exchange(code, strings.Repeat("x", 43)); res.StatusCode != 400 {
		t.Fatalf("wrong verifier = %d", res.StatusCode)
	}
	if res, _ := e.exchange(code, verifier); res.StatusCode != 400 {
		t.Fatalf("code must be consumed by the failed attempt, got %d", res.StatusCode)
	}
}

func TestWrongPINAndLockOverHTTP(t *testing.T) {
	e := newEnv(t)
	token := e.issue("u")
	e.login(token, "", "3947")
	res, out := e.login(token, "1111", "")
	if res.StatusCode != 401 || out["error"] != "wrong_pin" || out["remaining"] != float64(card.DefaultMaxAttempts-1) {
		t.Fatalf("wrong pin = %d %v", res.StatusCode, out)
	}
	for range card.DefaultMaxAttempts - 2 {
		e.login(token, "1111", "")
	}
	res, out = e.login(token, "1111", "")
	if res.StatusCode != 403 || out["error"] != "locked" {
		t.Fatalf("lock = %d %v", res.StatusCode, out)
	}
	res, out = e.do("GET", "/admin/v1/cards?subject=u", "Bearer "+adminKey, "", "")
	if res.StatusCode != 200 || out["locked"] != true {
		t.Fatalf("admin view = %v", out)
	}
	if res, _ := e.do("POST", "/admin/v1/cards/unlock", "Bearer "+adminKey, "application/json", `{"subject":"u"}`); res.StatusCode != 200 {
		t.Fatalf("unlock = %d", res.StatusCode)
	}
	if res, _ := e.login(token, "3947", ""); res.StatusCode != 200 {
		t.Fatalf("login after unlock = %d", res.StatusCode)
	}
}

func TestReissueAndRevokeOverHTTP(t *testing.T) {
	e := newEnv(t)
	old := e.issue("u")
	e.login(old, "", "3947")
	e.issue("u")
	if res, out := e.login(old, "3947", ""); res.StatusCode != 401 || out["error"] != "invalid_card" {
		t.Fatalf("old card = %d %v", res.StatusCode, out)
	}
	res, out := e.do("POST", "/admin/v1/cards/revoke", "Bearer "+adminKey, "application/json", `{"subject":"u"}`)
	if res.StatusCode != 200 || out["active"] != false || out["generation"] != float64(3) {
		t.Fatalf("revoke = %d %v", res.StatusCode, out)
	}
}

func TestAdminAuth(t *testing.T) {
	e := newEnv(t)
	for _, auth := range []string{"", "Bearer wrong", "Bearer myapp.wrong", "Bearer other.x"} {
		if res, _ := e.do("GET", "/admin/v1/cards", auth, "", ""); res.StatusCode != 401 {
			t.Errorf("auth %q = %d, want 401", auth, res.StatusCode)
		}
	}
}

func TestAuthorizeRejectsBadRequests(t *testing.T) {
	e := newEnv(t)
	// Unknown redirect URI: shown as an error page, never redirected.
	q := strings.Replace(authQuery(), url.QueryEscape(redirectURI), url.QueryEscape("https://evil.example/cb"), 1)
	if res, _ := e.do("GET", "/authorize?"+q, "", "", ""); res.StatusCode != 400 || res.Header.Get("Location") != "" {
		t.Fatalf("bad redirect = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// Missing PKCE: reported to the (valid) redirect URI.
	q = strings.Replace(authQuery(), "code_challenge_method=S256", "code_challenge_method=plain", 1)
	res, _ := e.do("GET", "/authorize?"+q, "", "", "")
	if res.StatusCode != 302 || !strings.Contains(res.Header.Get("Location"), "error=invalid_request") {
		t.Fatalf("no pkce = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestCardOfOtherClientIsRejected(t *testing.T) {
	e := newEnv(t)
	token := e.issue("u")
	q := url.Values{
		"response_type": {"code"}, "client_id": {"other"}, "redirect_uri": {"https://other.example/cb"},
		"scope": {"openid"}, "code_challenge": {challenge()}, "code_challenge_method": {"S256"},
	}.Encode()
	body, _ := json.Marshal(map[string]string{"query": q, "token": token, "newPin": "3947"})
	if res, out := e.do("POST", "/authorize/card", "", "application/json", string(body)); res.StatusCode != 401 || out["error"] != "invalid_card" {
		t.Fatalf("other client = %d %v", res.StatusCode, out)
	}
}

func TestAuthorizeCardRequiresJSON(t *testing.T) {
	e := newEnv(t)
	if res, _ := e.do("POST", "/authorize/card", "", "application/x-www-form-urlencoded", "query=x"); res.StatusCode != 415 {
		t.Fatalf("form post = %d, want 415", res.StatusCode)
	}
}

func TestResolveCard(t *testing.T) {
	e := newEnv(t)
	token := e.issue("u")
	res, out := e.do("POST", "/card/resolve", "", "application/json", `{"token":"`+token+`"}`)
	if res.StatusCode != 200 || out["initiateLoginUri"] != "https://rp.example/login/card?iss="+url.QueryEscape(e.ts.URL) {
		t.Fatalf("resolve = %d %v", res.StatusCode, out)
	}
}

func jwksKey(t *testing.T, e *env) any {
	t.Helper()
	res, err := http.Get(e.ts.URL + "/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var set struct {
		Keys []struct{ X, Y string } `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("jwks: %v", err)
	}
	return parseECKey(t, set.Keys[0].X, set.Keys[0].Y)
}

func TestIssueWithActivationDeadline(t *testing.T) {
	e := newEnv(t)
	res, out := e.do("POST", "/admin/v1/cards/issue", "Bearer "+adminKey, "application/json", `{"subject":"u","activateWithinSeconds":86400}`)
	if res.StatusCode != 200 || out["card"].(map[string]any)["activateBy"] == nil {
		t.Fatalf("issue = %d %v", res.StatusCode, out)
	}
	for _, bad := range []string{`-1`, `2592001`} {
		if res, _ := e.do("POST", "/admin/v1/cards/issue", "Bearer "+adminKey, "application/json", `{"subject":"u","activateWithinSeconds":`+bad+`}`); res.StatusCode != 400 {
			t.Errorf("activateWithinSeconds=%s: status %d, want 400", bad, res.StatusCode)
		}
	}
}

func TestIssueWithExpiry(t *testing.T) {
	e := newEnv(t)
	res, out := e.do("POST", "/admin/v1/cards/issue", "Bearer "+adminKey, "application/json", `{"subject":"u","expiresInSeconds":259200}`)
	if res.StatusCode != 200 || out["card"].(map[string]any)["expiresAt"] == nil {
		t.Fatalf("issue = %d %v", res.StatusCode, out)
	}
	_, loginOut := e.login(out["token"].(string), "", "3947")
	_, tok := e.exchange(e.codeFrom(loginOut["redirect"].(string)), verifier)
	var claims oidc.IDTokenClaims
	if _, err := jwt.ParseWithClaims(tok["id_token"].(string), &claims, func(*jwt.Token) (any, error) {
		return jwksKey(t, e), nil
	}); err != nil {
		t.Fatal(err)
	}
	want := time.Now().Add(72 * time.Hour).Unix()
	if claims.CardExpiresAt < want-60 || claims.CardExpiresAt > want+60 {
		t.Fatalf("card_exp = %d, want about %d", claims.CardExpiresAt, want)
	}
	for _, bad := range []string{`-1`, `31536001`} {
		if res, _ := e.do("POST", "/admin/v1/cards/issue", "Bearer "+adminKey, "application/json", `{"subject":"u","expiresInSeconds":`+bad+`}`); res.StatusCode != 400 {
			t.Errorf("expiresInSeconds=%s: status %d, want 400", bad, res.StatusCode)
		}
	}
}

func TestNoExpiryMeansNoCardExpClaim(t *testing.T) {
	e := newEnv(t)
	_, loginOut := e.login(e.issue("u"), "", "3947")
	_, tok := e.exchange(e.codeFrom(loginOut["redirect"].(string)), verifier)
	parts := strings.Split(tok["id_token"].(string), ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if strings.Contains(string(payload), "card_exp") {
		t.Fatalf("card_exp present for a card without expiry: %s", payload)
	}
}

func TestTopLevelRoutingAndHeaders(t *testing.T) {
	e := newEnv(t)
	tests := []struct {
		method, path string
		want         int
	}{
		{"GET", "/", 200},
		{"HEAD", "/", 200},
		{"HEAD", "/jwks.json", 200},
		{"GET", "/no-such-page", 404},
		{"OPTIONS", "/token", 204},
		{"OPTIONS", "/authorize/card", 405}, // no CORS for the login page API
	}
	for _, tt := range tests {
		res, _ := e.do(tt.method, tt.path, "", "", "")
		if res.StatusCode != tt.want {
			t.Errorf("%s %s = %d, want %d", tt.method, tt.path, res.StatusCode, tt.want)
		}
		if res.Header.Get("Strict-Transport-Security") == "" || res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s %s: missing HSTS or nosniff: %v", tt.method, tt.path, res.Header)
		}
	}
	res, _ := e.do("GET", "/", "", "", "")
	if res.Header.Get("Content-Security-Policy") == "" || res.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("home page lacks page headers: %v", res.Header)
	}
}
