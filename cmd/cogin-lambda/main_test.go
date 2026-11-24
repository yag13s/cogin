package main

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"

	"github.com/yag13s/cogin/internal/setup"
)

// TestLambdaAdapter sends API Gateway HTTP API (v2) events through the same
// adapter the Lambda uses, to catch path, header or body handling that only
// breaks behind API Gateway.
func TestLambdaAdapter(t *testing.T) {
	t.Setenv("COGIN_DEV", "1")
	t.Setenv("COGIN_CONFIG_JSON", `{"issuer":"https://auth.example","clients":[{"id":"app","name":"App","redirectUris":["https://app.example/cb"]}]}`)
	srv, err := setup.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	adapter := httpadapter.NewV2(srv.Handler())

	get := func(path, query string) events.APIGatewayV2HTTPResponse {
		t.Helper()
		resp, err := adapter.ProxyWithContext(context.Background(), events.APIGatewayV2HTTPRequest{
			Version:        "2.0",
			RawPath:        path,
			RawQueryString: query,
			Headers:        map[string]string{"host": "auth.example"},
			RequestContext: events.APIGatewayV2HTTPRequestContext{
				HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: "GET", Path: path},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	if r := get("/.well-known/openid-configuration", ""); r.StatusCode != 200 || !strings.Contains(r.Body, `"issuer":"https://auth.example"`) {
		t.Errorf("discovery = %d %.100s", r.StatusCode, r.Body)
	}
	if r := get("/static/vendor/jsQR.js", ""); r.StatusCode != 200 || !strings.Contains(body(t, r), "jsQR") {
		t.Errorf("jsQR = %d (base64=%v)", r.StatusCode, r.IsBase64Encoded)
	}
	q := "response_type=code&client_id=app&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=openid&code_challenge=x&code_challenge_method=S256"
	if r := get("/authorize", q); r.StatusCode != 200 || r.Headers["X-Frame-Options"] != "DENY" {
		t.Errorf("authorize = %d %v", r.StatusCode, r.Headers)
	}
}

func body(t *testing.T, r events.APIGatewayV2HTTPResponse) string {
	t.Helper()
	if !r.IsBase64Encoded {
		return r.Body
	}
	b, err := base64.StdEncoding.DecodeString(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
