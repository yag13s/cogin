package card

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// TokenPrefix marks a cogin card token so it can be told apart from other
// secrets (and found by secret scanners) at a glance.
const TokenPrefix = "cgc_"

const (
	cardIDBytes = 8  // 64 bits: only needs to be unique, it is not secret
	secretBytes = 32 // 256 bits: brute force is not a realistic attack
)

// newToken returns a fresh card id and the full token "cgc_{id}_{secret}".
func newToken() (cardID, token string, err error) {
	idRaw := make([]byte, cardIDBytes)
	if _, err := rand.Read(idRaw); err != nil {
		return "", "", err
	}
	secret := make([]byte, secretBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", "", err
	}
	cardID = hex.EncodeToString(idRaw)
	token = TokenPrefix + cardID + "_" + base64.RawURLEncoding.EncodeToString(secret)
	return cardID, token, nil
}

// parseToken extracts the card id. It only checks the shape; whether the
// secret is right is decided by comparing hashes against the stored card.
func parseToken(token string) (cardID string, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(token), TokenPrefix)
	if !found {
		return "", false
	}
	id, secret, found := strings.Cut(rest, "_")
	if !found || len(id) != cardIDBytes*2 || secret == "" {
		return "", false
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", false
	}
	return id, true
}

// hashToken hashes the whole token. A plain SHA-256 is enough because the
// token has 256 bits of entropy; slow hashes only matter for guessable input.
func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return sum[:]
}
