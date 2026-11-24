// Command cogin-lambda runs cogin on AWS Lambda behind an API Gateway HTTP
// API (payload format 2.0). Configuration is the same as cmd/cogin; in
// production secrets come from SSM via the *_SSM_PATH variables.
package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"

	"github.com/yag13s/cogin/internal/setup"
)

func main() {
	// Built once per cold start: SSM reads and key parsing are not repeated
	// on warm invocations.
	srv, err := setup.Build(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	lambda.Start(httpadapter.NewV2(srv.Handler()).ProxyWithContext)
}
