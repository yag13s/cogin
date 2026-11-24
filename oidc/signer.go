package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Token lifetimes. ID tokens are short because relying parties exchange them
// for their own sessions right away; nothing should hold on to them.
const (
	IDTokenTTL     = 5 * time.Minute
	AccessTokenTTL = 5 * time.Minute
)

// Signer signs tokens with an ES256 key and publishes it as a JWKS.
// ES256 (not HS256) so relying parties verify with the public key and never
// hold a secret that could mint tokens.
type Signer struct {
	issuer string
	key    *ecdsa.PrivateKey
	kid    string
}

// NewSigner returns a Signer for the issuer URL.
func NewSigner(issuer string, key *ecdsa.PrivateKey) (*Signer, error) {
	if key.Curve != elliptic.P256() {
		return nil, errors.New("oidc: signing key must be P-256")
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &Signer{issuer: issuer, key: key, kid: base64.RawURLEncoding.EncodeToString(sum[:12])}, nil
}

// ParseKeyPEM reads a PKCS#8 or SEC1 EC private key.
func ParseKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("oidc: no PEM block in signing key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if ec, ok := k.(*ecdsa.PrivateKey); ok {
			return ec, nil
		}
		return nil, errors.New("oidc: signing key is not ECDSA")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// GenerateKey returns a new P-256 key (for development).
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Issuer returns the issuer URL.
func (s *Signer) Issuer() string { return s.issuer }

// IDTokenClaims are the claims cogin puts in an ID token.
type IDTokenClaims struct {
	jwt.RegisteredClaims
	AuthTime int64    `json:"auth_time"`
	Nonce    string   `json:"nonce,omitempty"`
	AMR      []string `json:"amr"`
	Name     string   `json:"name,omitempty"`

	// CardGeneration is the generation of the card used to log in. A relying
	// party that stores it with the session can drop the session as soon as
	// the card is re-issued or revoked.
	CardGeneration int64 `json:"card_gen"`

	// CardExpiresAt (unix seconds) is when the card stops being valid, if it
	// has an expiry. Sessions derived from this login should end by then.
	CardExpiresAt int64 `json:"card_exp,omitempty"`
}

// IDToken signs an ID token for a redeemed code.
func (s *Signer) IDToken(c *AuthCode, now time.Time) (string, error) {
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   c.Subject,
			Audience:  jwt.ClaimStrings{c.ClientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(IDTokenTTL)),
		},
		AuthTime: c.AuthTime.Unix(),
		Nonce:    c.Nonce,
		// "pin" is the registered RFC 8176 value. The card itself is a copyable
		// QR code, so it is deliberately not claimed as "hwk" or "mfa".
		AMR:            []string{"pin"},
		Name:           c.Name,
		CardGeneration: c.Generation,
	}
	if c.CardExpiresAt != nil {
		claims.CardExpiresAt = c.CardExpiresAt.Unix()
	}
	return s.sign(claims, "JWT")
}

// AccessTokenClaims are the claims of the access token for /userinfo.
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	ClientID string `json:"client_id"`
	Name     string `json:"name,omitempty"`
	CardGen  int64  `json:"card_gen"`
}

// AccessToken signs an RFC 9068 access token whose only audience is cogin's
// own /userinfo.
func (s *Signer) AccessToken(c *AuthCode, now time.Time) (string, error) {
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   c.Subject,
			Audience:  jwt.ClaimStrings{s.issuer + "/userinfo"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenTTL)),
		},
		ClientID: c.ClientID,
		Name:     c.Name,
		CardGen:  c.Generation,
	}
	return s.sign(claims, "at+jwt")
}

// VerifyAccessToken checks an access token issued by AccessToken.
func (s *Signer) VerifyAccessToken(raw string) (*AccessTokenClaims, error) {
	var claims AccessTokenClaims
	tok, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		if t.Header["typ"] != "at+jwt" {
			// Without this an ID token (same key, same issuer) would pass.
			return nil, errors.New("not an access token")
		}
		return &s.key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(s.issuer), jwt.WithAudience(s.issuer+"/userinfo"))
	if err != nil || !tok.Valid {
		return nil, errors.New("invalid access token")
	}
	return &claims, nil
}

func (s *Signer) sign(claims jwt.Claims, typ string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["kid"] = s.kid
	t.Header["typ"] = typ
	return t.SignedString(s.key)
}

// JWKS returns the public key set.
func (s *Signer) JWKS() json.RawMessage {
	pub := s.key.PublicKey
	ecdh, err := pub.ECDH()
	if err != nil {
		panic(err) // a P-256 key always converts
	}
	raw := ecdh.Bytes() // 0x04 || X || Y
	b64 := base64.RawURLEncoding.EncodeToString
	set := map[string]any{"keys": []map[string]string{{
		"kty": "EC",
		"crv": "P-256",
		"alg": "ES256",
		"use": "sig",
		"kid": s.kid,
		"x":   b64(raw[1:33]),
		"y":   b64(raw[33:65]),
	}}}
	out, _ := json.Marshal(set)
	return out
}
