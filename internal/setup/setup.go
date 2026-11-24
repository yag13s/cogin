// Package setup builds a cogin server from the environment. Both entry points
// (the local HTTP server and the Lambda handler) use it so they cannot drift.
//
// Every secret can come from the environment directly or, with the
// *_SSM_PATH variant, from an SSM Parameter Store SecureString (production).
package setup

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/yag13s/cogin/card"
	"github.com/yag13s/cogin/oidc"
	"github.com/yag13s/cogin/server"
	"github.com/yag13s/cogin/store/dynamostore"
	"github.com/yag13s/cogin/store/memstore"
)

// fileConfig is the JSON from COGIN_CONFIG_JSON, COGIN_CONFIG_SSM_PATH or
// the file at COGIN_CONFIG.
type fileConfig struct {
	Issuer  string         `json:"issuer"`
	Clients []*oidc.Client `json:"clients"`
}

type loader struct {
	ctx context.Context
	ssm *ssm.Client // created on first use
	dev bool
}

// Build returns a configured server. COGIN_DEV=1 allows an in-memory store,
// an ephemeral signing key and a fixed pepper (never in production).
func Build(ctx context.Context) (*server.Server, error) {
	l := &loader{ctx: ctx, dev: os.Getenv("COGIN_DEV") == "1"}

	cfg, err := l.config()
	if err != nil {
		return nil, err
	}
	clients := oidc.Clients{}
	for _, c := range cfg.Clients {
		if c.ID == "" || strings.Contains(c.ID, ".") {
			return nil, fmt.Errorf("client id %q must be non-empty and contain no '.'", c.ID)
		}
		clients[c.ID] = c
	}

	key, err := l.signingKey()
	if err != nil {
		return nil, err
	}
	signer, err := oidc.NewSigner(cfg.Issuer, key)
	if err != nil {
		return nil, err
	}
	pepper, err := l.pepper()
	if err != nil {
		return nil, err
	}

	var cardStore card.Store
	var codeStore oidc.CodeStore
	switch os.Getenv("COGIN_STORE") {
	case "", "memory":
		if !l.dev {
			return nil, errors.New("the memory store loses all cards on restart; set COGIN_STORE=dynamodb or COGIN_DEV=1")
		}
		m := memstore.New()
		cardStore, codeStore = m, m
	case "dynamodb":
		awsCfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, err
		}
		db := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
			if ep := os.Getenv("DYNAMODB_ENDPOINT"); ep != "" {
				o.BaseEndpoint = aws.String(ep)
			}
		})
		d := dynamostore.New(db, envOr("COGIN_TABLE", "cogin"))
		cardStore, codeStore = d, d
	default:
		return nil, fmt.Errorf("unknown COGIN_STORE %q", os.Getenv("COGIN_STORE"))
	}

	cards, err := card.NewService(cardStore, pepper)
	if err != nil {
		return nil, err
	}
	log.Printf("cogin: issuer %s, %d clients", cfg.Issuer, len(clients))
	return &server.Server{Issuer: cfg.Issuer, Clients: clients, Cards: cards, Codes: codeStore, Signer: signer}, nil
}

// secret returns env[name], else the SSM parameter named by env[name_SSM_PATH].
func (l *loader) secret(name string) (string, error) {
	if v := os.Getenv(name); v != "" {
		return v, nil
	}
	path := os.Getenv(name + "_SSM_PATH")
	if path == "" {
		return "", nil
	}
	if l.ssm == nil {
		awsCfg, err := config.LoadDefaultConfig(l.ctx)
		if err != nil {
			return "", err
		}
		l.ssm = ssm.NewFromConfig(awsCfg)
	}
	out, err := l.ssm.GetParameter(l.ctx, &ssm.GetParameterInput{Name: aws.String(path), WithDecryption: aws.Bool(true)})
	if err != nil {
		return "", fmt.Errorf("read %s from SSM %s: %w", name, path, err)
	}
	return aws.ToString(out.Parameter.Value), nil
}

func (l *loader) config() (*fileConfig, error) {
	raw, err := l.secret("COGIN_CONFIG_JSON")
	if err != nil {
		return nil, err
	}
	if raw == "" {
		path := envOr("COGIN_CONFIG", "cogin.json")
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		raw = string(b)
	}
	var cfg fileConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if v := os.Getenv("COGIN_ISSUER"); v != "" {
		cfg.Issuer = v
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if cfg.Issuer == "" {
		return nil, errors.New("issuer is required (config issuer or COGIN_ISSUER)")
	}
	return &cfg, nil
}

func (l *loader) signingKey() (*ecdsa.PrivateKey, error) {
	pemData, err := l.secret("COGIN_SIGNING_KEY")
	if err != nil {
		return nil, err
	}
	if pemData == "" {
		if p := os.Getenv("COGIN_SIGNING_KEY_FILE"); p != "" {
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("read signing key: %w", err)
			}
			pemData = string(b)
		}
	}
	if pemData == "" {
		if !l.dev {
			return nil, errors.New("COGIN_SIGNING_KEY (or _FILE / _SSM_PATH) is required; generate one with `cogin gen-key`")
		}
		log.Print("WARNING: using an ephemeral signing key (COGIN_DEV=1); tokens break on restart")
		return oidc.GenerateKey()
	}
	return oidc.ParseKeyPEM([]byte(pemData))
}

// pepper must never change once PINs exist: every stored PIN hash depends on
// it, so a new pepper silently invalidates all PINs.
func (l *loader) pepper() ([]byte, error) {
	v, err := l.secret("COGIN_PIN_PEPPER")
	if err != nil {
		return nil, err
	}
	if v == "" {
		if !l.dev {
			return nil, errors.New("COGIN_PIN_PEPPER (or _SSM_PATH) is required: 32+ random bytes, base64")
		}
		log.Print("WARNING: using a fixed development PIN pepper (COGIN_DEV=1)")
		return []byte("cogin-development-pepper-do-not-use-in-production"), nil
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return nil, errors.New("COGIN_PIN_PEPPER must be base64")
	}
	return b, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
