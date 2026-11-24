// Command cogin runs the cogin OpenID Connect provider as a plain HTTP server
// (local development or a container), and has helpers to generate a signing
// key, a PIN pepper and client credentials.
//
//	cogin                 serve (configured by environment, see README)
//	cogin gen-key         print a new ES256 signing key (PEM)
//	cogin gen-pepper      print a new PIN pepper (base64)
//	cogin new-client ID   print a client secret, an admin key and their hashes
package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yag13s/cogin/internal/setup"
	"github.com/yag13s/cogin/oidc"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "gen-key":
			genKey()
			return
		case "gen-pepper":
			fmt.Println(base64.StdEncoding.EncodeToString(randomBytes(32)))
			return
		case "new-client":
			if len(os.Args) < 3 {
				log.Fatal("usage: cogin new-client CLIENT_ID")
			}
			newClient(os.Args[2])
			return
		default:
			log.Fatalf("unknown command %q", os.Args[1])
		}
	}

	srv, err := setup.Build(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	addr := os.Getenv("COGIN_ADDR")
	if addr == "" {
		addr = ":8090"
	}
	log.Printf("cogin listening on %s", addr)
	hs := &http.Server{Addr: addr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(hs.ListenAndServe())
}

func genKey() {
	k, err := oidc.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		log.Fatal(err)
	}
	_ = pem.Encode(os.Stdout, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return b
}

func newClient(id string) {
	if strings.Contains(id, ".") {
		log.Fatal("client id must not contain '.'")
	}
	secret := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	adminKey := id + "." + base64.RawURLEncoding.EncodeToString(randomBytes(32))
	fmt.Printf("# Give these to the relying party (shown once):\n")
	fmt.Printf("client_secret = %s\n", secret)
	fmt.Printf("admin_key     = %s\n\n", adminKey)
	fmt.Printf("# Put these in cogin's config:\n")
	fmt.Printf("\"secretHash\": %q,\n", oidc.HashSecret(secret))
	fmt.Printf("\"adminKeyHash\": %q\n", oidc.HashSecret(adminKey))
}
