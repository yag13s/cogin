package main

import (
	"fmt"
	"os"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/jsii-runtime-go"

	"github.com/yag13s/cogin/infra/stacks"
)

// Deployment settings come from CDK context, so nothing about a particular
// deployment lives in the code. Pass them with -c key=value, or put them in
// infra/cdk.context.json (git-ignored), e.g.
//
//	{
//	  "domainName": "auth.example.com",
//	  "hostedZoneId": "Z0123456789ABCDEFGHIJ",
//	  "hostedZoneName": "example.com"
//	}
//
// Optional: "region" (default ap-northeast-1), "tableName" (default cogin),
// "ssmPrefix" (default /cogin).
func main() {
	defer jsii.Close()

	app := awscdk.NewApp(nil)

	ctx := func(key, def string) string {
		if v, ok := app.Node().TryGetContext(jsii.String(key)).(string); ok && v != "" {
			return v
		}
		if def == "" {
			fmt.Fprintf(os.Stderr, "missing CDK context %q (pass -c %s=... or set it in infra/cdk.context.json)\n", key, key)
			os.Exit(1)
		}
		return def
	}

	stacks.NewCoginStack(app, "CoginStack", &stacks.CoginStackProps{
		StackProps: awscdk.StackProps{
			Env: &awscdk.Environment{
				Account: jsii.String(os.Getenv("CDK_DEFAULT_ACCOUNT")),
				Region:  jsii.String(ctx("region", "ap-northeast-1")),
			},
			Description: jsii.String("cogin - QR login card OIDC provider (Lambda, HTTP API, DynamoDB)"),
		},
		Config: &stacks.Config{
			DomainName:     ctx("domainName", ""),
			HostedZoneID:   ctx("hostedZoneId", ""),
			HostedZoneName: ctx("hostedZoneName", ""),
			TableName:      ctx("tableName", "cogin"),
			SSMPrefix:      ctx("ssmPrefix", "/cogin"),
			RateLimit:      20,
			BurstLimit:     40,
		},
	})

	app.Synth(nil)
}
