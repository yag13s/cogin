// Package oidc holds the protocol pieces of cogin's OpenID Connect provider:
// client registry, authorization request validation, PKCE, authorization
// codes and ID token signing. HTTP wiring lives in package server.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Client is a relying party allowed to use cogin.
type Client struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	// RedirectURIs must match the authorization request exactly.
	RedirectURIs []string `json:"redirectUris"`

	// SecretHash is the hex SHA-256 of the client secret. Empty means a
	// public client (browser or native app) that relies on PKCE alone.
	SecretHash string `json:"secretHash,omitempty"`

	// AdminKeyHash is the hex SHA-256 of the key the client's backend uses
	// for the card management API. Empty disables the management API.
	AdminKeyHash string `json:"adminKeyHash,omitempty"`

	// InitiateLoginURI is where a card scanned outside any login (for example
	// with a phone camera) sends the browser so the client can start an
	// authorization request (OIDC Core 4, third-party initiated login).
	InitiateLoginURI string `json:"initiateLoginUri,omitempty"`
}

// Confidential reports whether the client must authenticate at /token.
func (c *Client) Confidential() bool { return c.SecretHash != "" }

// CheckSecret compares a presented secret with SecretHash in constant time.
func (c *Client) CheckSecret(secret string) bool {
	return checkHash(c.SecretHash, secret)
}

// CheckAdminKey compares a presented admin key with AdminKeyHash.
func (c *Client) CheckAdminKey(key string) bool {
	return checkHash(c.AdminKeyHash, key)
}

func checkHash(wantHex, presented string) bool {
	if wantHex == "" || presented == "" {
		return false
	}
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		return false
	}
	got := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(want, got[:]) == 1
}

// HashSecret returns the hex SHA-256 used for SecretHash and AdminKeyHash.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// Clients is the registry of relying parties, keyed by client id.
type Clients map[string]*Client

// AuthRequest is a validated authorization request.
type AuthRequest struct {
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	State         string `json:"state,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
	CodeChallenge string `json:"code_challenge"`
	Scope         string `json:"scope"`
}

// AuthError is an authorization error that may be reported back to the
// client's redirect URI. Redirectable is false when the client or redirect
// URI itself is wrong: redirecting then would make cogin an open redirector,
// so the error is only shown to the user.
type AuthError struct {
	Code         string
	Description  string
	Redirectable bool
}

func (e *AuthError) Error() string { return e.Code + ": " + e.Description }

// ParseAuthRequest validates the query of an authorization request.
// Only the authorization code flow with PKCE S256 is supported, as OAuth 2.1
// requires.
func (cs Clients) ParseAuthRequest(q url.Values) (*AuthRequest, *Client, error) {
	client := cs[q.Get("client_id")]
	if client == nil {
		return nil, nil, &AuthError{Code: "invalid_client", Description: "unknown client_id"}
	}
	redirect := q.Get("redirect_uri")
	if !slices.Contains(client.RedirectURIs, redirect) {
		return nil, nil, &AuthError{Code: "invalid_request", Description: "redirect_uri is not registered"}
	}
	req := &AuthRequest{
		ClientID:      client.ID,
		RedirectURI:   redirect,
		State:         q.Get("state"),
		Nonce:         q.Get("nonce"),
		CodeChallenge: q.Get("code_challenge"),
		Scope:         q.Get("scope"),
	}
	fail := func(code, desc string) (*AuthRequest, *Client, error) {
		return req, client, &AuthError{Code: code, Description: desc, Redirectable: true}
	}
	if q.Get("response_type") != "code" {
		return fail("unsupported_response_type", "only response_type=code is supported")
	}
	if !slices.Contains(strings.Fields(req.Scope), "openid") {
		return fail("invalid_scope", "scope must include openid")
	}
	if req.CodeChallenge == "" || q.Get("code_challenge_method") != "S256" {
		return fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
	}
	if q.Get("prompt") == "none" {
		// A card login always needs the holder present.
		return fail("login_required", "cogin cannot log in without user interaction")
	}
	return req, client, nil
}

// ErrorRedirect builds the redirect URI carrying an authorization error.
func (r *AuthRequest) ErrorRedirect(code, desc string) string {
	v := url.Values{"error": {code}}
	if desc != "" {
		v.Set("error_description", desc)
	}
	return r.redirect(v)
}

// CodeRedirect builds the redirect URI carrying an authorization code.
func (r *AuthRequest) CodeRedirect(code, issuer string) string {
	// iss is included per RFC 9207 so clients can detect mix-up attacks.
	return r.redirect(url.Values{"code": {code}, "iss": {issuer}})
}

func (r *AuthRequest) redirect(v url.Values) string {
	if r.State != "" {
		v.Set("state", r.State)
	}
	sep := "?"
	if strings.Contains(r.RedirectURI, "?") {
		sep = "&"
	}
	return r.RedirectURI + sep + v.Encode()
}

// VerifyPKCE checks an S256 code verifier against its challenge.
func VerifyPKCE(challenge, verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

// AuthCode is what an authorization code stands for until it is redeemed.
type AuthCode struct {
	ClientID    string `json:"clientId" dynamodbav:"clientId"`
	RedirectURI string `json:"redirectUri" dynamodbav:"redirectUri"`
	Subject     string `json:"subject" dynamodbav:"subject"`
	Name        string `json:"name,omitempty" dynamodbav:"name,omitempty"`
	Generation  int64  `json:"generation" dynamodbav:"generation"`
	// CardExpiresAt is the card's validity end, passed on as card_exp so a
	// relying party does not keep a session open past it.
	CardExpiresAt *time.Time `json:"cardExpiresAt,omitempty" dynamodbav:"cardExpiresAt,omitempty"`
	Nonce         string     `json:"nonce,omitempty" dynamodbav:"nonce,omitempty"`
	CodeChallenge string     `json:"codeChallenge" dynamodbav:"codeChallenge"`
	AuthTime      time.Time  `json:"authTime" dynamodbav:"authTime"`
}

// CodeTTL is how long an authorization code can be redeemed.
const CodeTTL = 5 * time.Minute

// CodeStore keeps authorization codes by hash.
type CodeStore interface {
	PutCode(ctx context.Context, hash string, code *AuthCode, ttl time.Duration) error
	// ConsumeCode returns and deletes the code in one step, so a code can be
	// redeemed at most once even under concurrent requests. It returns nil
	// for unknown or expired codes.
	ConsumeCode(ctx context.Context, hash string) (*AuthCode, error)
}

// NewCode returns a random authorization code and the hash to store it under.
func NewCode() (code, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	code = base64.RawURLEncoding.EncodeToString(b)
	return code, HashCode(code), nil
}

// HashCode returns the storage key of a code. Storing only the hash means a
// read of the table does not yield redeemable codes.
func HashCode(code string) string {
	return HashSecret(code)
}

// ErrInvalidGrant is returned for codes that are unknown, expired, already
// used, or presented with the wrong client, redirect URI or verifier.
var ErrInvalidGrant = errors.New("invalid_grant")

// Redeem checks a consumed code against the token request.
func (c *AuthCode) Redeem(clientID, redirectURI, verifier string) error {
	if c == nil || c.ClientID != clientID || c.RedirectURI != redirectURI || !VerifyPKCE(c.CodeChallenge, verifier) {
		return ErrInvalidGrant
	}
	return nil
}
