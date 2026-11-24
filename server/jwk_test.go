package server_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

// parseECKey rebuilds a P-256 public key from JWK coordinates.
func parseECKey(t *testing.T, x, y string) *ecdsa.PublicKey {
	t.Helper()
	xb, err1 := base64.RawURLEncoding.DecodeString(x)
	yb, err2 := base64.RawURLEncoding.DecodeString(y)
	if err1 != nil || err2 != nil {
		t.Fatal("bad jwk coordinates")
	}
	raw := append(append([]byte{4}, xb...), yb...)
	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*ecdsa.PublicKey)
}
