// Package stacks defines cogin's AWS infrastructure.
package stacks

import (
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsapigatewayv2"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsapigatewayv2integrations"
	"github.com/aws/aws-cdk-go/awscdk/v2/awscertificatemanager"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsdynamodb"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	"github.com/aws/aws-cdk-go/awscdk/v2/awslogs"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsroute53"
	"github.com/aws/aws-cdk-go/awscdk/v2/awsroute53targets"
	"github.com/aws/constructs-go/constructs/v10"
	"github.com/aws/jsii-runtime-go"
)

// Config holds cogin's deployment settings.
type Config struct {
	// DomainName is the issuer host, e.g. auth.example.com.
	DomainName string
	// HostedZoneID / HostedZoneName identify the existing Route53 zone the
	// domain lives in (the zone itself is not managed here).
	HostedZoneID   string
	HostedZoneName string
	TableName      string
	// SSMPrefix is where the secrets live: {prefix}/signing-key,
	// {prefix}/pin-pepper (SecureString) and {prefix}/config (String).
	// They are created by hand (see README), never by CDK, so the values
	// never pass through CloudFormation.
	SSMPrefix string
	// Throttle for the whole API. Card tokens cannot be guessed and PINs lock
	// after a few tries, so this is a cost and abuse ceiling, not the brute-force
	// defence.
	RateLimit  float64
	BurstLimit float64
}

// CoginStackProps are the stack's properties.
type CoginStackProps struct {
	awscdk.StackProps
	Config *Config
}

// NewCoginStack creates DynamoDB, the Lambda function, the HTTP API with a
// custom domain, and its DNS record.
func NewCoginStack(scope constructs.Construct, id string, props *CoginStackProps) awscdk.Stack {
	stack := awscdk.NewStack(scope, &id, &props.StackProps)
	cfg := props.Config

	// Losing this table means every issued card stops working, so it is
	// retained on stack deletion, protected from deletion and backed up.
	table := awsdynamodb.NewTable(stack, jsii.String("CoginTable"), &awsdynamodb.TableProps{
		TableName:           jsii.String(cfg.TableName),
		PartitionKey:        &awsdynamodb.Attribute{Name: jsii.String("PK"), Type: awsdynamodb.AttributeType_STRING},
		SortKey:             &awsdynamodb.Attribute{Name: jsii.String("SK"), Type: awsdynamodb.AttributeType_STRING},
		BillingMode:         awsdynamodb.BillingMode_PAY_PER_REQUEST,
		TimeToLiveAttribute: jsii.String("ttl"),
		PointInTimeRecoverySpecification: &awsdynamodb.PointInTimeRecoverySpecification{
			PointInTimeRecoveryEnabled: jsii.Bool(true),
		},
		DeletionProtection: jsii.Bool(true),
		RemovalPolicy:      awscdk.RemovalPolicy_RETAIN,
	})

	ssmParam := func(name string) string { return cfg.SSMPrefix + "/" + name }

	logGroup := awslogs.NewLogGroup(stack, jsii.String("CoginLogs"), &awslogs.LogGroupProps{
		LogGroupName:  jsii.String("/aws/lambda/cogin"),
		Retention:     awslogs.RetentionDays_ONE_MONTH,
		RemovalPolicy: awscdk.RemovalPolicy_DESTROY,
	})

	fn := awslambda.NewFunction(stack, jsii.String("CoginFunction"), &awslambda.FunctionProps{
		FunctionName: jsii.String("cogin"),
		Description:  jsii.String("cogin - QR login card OpenID Connect provider"),
		Runtime:      awslambda.Runtime_PROVIDED_AL2023(),
		Handler:      jsii.String("bootstrap"),
		Code:         awslambda.Code_FromAsset(jsii.String("../dist"), nil),
		Architecture: awslambda.Architecture_ARM_64(),
		MemorySize:   jsii.Number(256),
		Timeout:      awscdk.Duration_Seconds(jsii.Number(10)),
		Environment: &map[string]*string{
			"COGIN_ISSUER":               jsii.String("https://" + cfg.DomainName),
			"COGIN_STORE":                jsii.String("dynamodb"),
			"COGIN_TABLE":                table.TableName(),
			"COGIN_CONFIG_JSON_SSM_PATH": jsii.String(ssmParam("config")),
			"COGIN_SIGNING_KEY_SSM_PATH": jsii.String(ssmParam("signing-key")),
			"COGIN_PIN_PEPPER_SSM_PATH":  jsii.String(ssmParam("pin-pepper")),
		},
		LogGroup: logGroup,
	})
	table.GrantReadWriteData(fn)
	fn.AddToRolePolicy(awsiam.NewPolicyStatement(&awsiam.PolicyStatementProps{
		Actions: &[]*string{jsii.String("ssm:GetParameter")},
		Resources: &[]*string{
			stack.FormatArn(&awscdk.ArnComponents{Service: jsii.String("ssm"), Resource: jsii.String("parameter"), ResourceName: jsii.String(ssmParam("*")[1:])}),
		},
	}))

	zone := awsroute53.HostedZone_FromHostedZoneAttributes(stack, jsii.String("Zone"), &awsroute53.HostedZoneAttributes{
		HostedZoneId: jsii.String(cfg.HostedZoneID),
		ZoneName:     jsii.String(cfg.HostedZoneName),
	})
	cert := awscertificatemanager.NewCertificate(stack, jsii.String("Certificate"), &awscertificatemanager.CertificateProps{
		DomainName: jsii.String(cfg.DomainName),
		Validation: awscertificatemanager.CertificateValidation_FromDns(zone),
	})
	domain := awsapigatewayv2.NewDomainName(stack, jsii.String("Domain"), &awsapigatewayv2.DomainNameProps{
		DomainName:  jsii.String(cfg.DomainName),
		Certificate: cert,
	})

	api := awsapigatewayv2.NewHttpApi(stack, jsii.String("CoginHttpApi"), &awsapigatewayv2.HttpApiProps{
		ApiName: jsii.String("cogin"),
		// The stage is created below so it can carry the throttle.
		CreateDefaultStage: jsii.Bool(false),
		// Only the custom domain is reachable: the issuer URL is part of every
		// token, and the throttle should not be bypassable via execute-api.
		DisableExecuteApiEndpoint: jsii.Bool(true),
	})
	integration := awsapigatewayv2integrations.NewHttpLambdaIntegration(jsii.String("CoginIntegration"), fn, nil)
	for _, path := range []string{"/", "/{proxy+}"} {
		api.AddRoutes(&awsapigatewayv2.AddRoutesOptions{
			Path:        jsii.String(path),
			Methods:     &[]awsapigatewayv2.HttpMethod{awsapigatewayv2.HttpMethod_ANY},
			Integration: integration,
		})
	}
	awsapigatewayv2.NewHttpStage(stack, jsii.String("DefaultStage"), &awsapigatewayv2.HttpStageProps{
		HttpApi:    api,
		StageName:  jsii.String("$default"),
		AutoDeploy: jsii.Bool(true),
		Throttle: &awsapigatewayv2.ThrottleSettings{
			RateLimit:  jsii.Number(cfg.RateLimit),
			BurstLimit: jsii.Number(cfg.BurstLimit),
		},
		DomainMapping: &awsapigatewayv2.DomainMappingOptions{DomainName: domain},
	})

	awsroute53.NewARecord(stack, jsii.String("AliasRecord"), &awsroute53.ARecordProps{
		Zone:       zone,
		RecordName: jsii.String(cfg.DomainName),
		Target: awsroute53.RecordTarget_FromAlias(awsroute53targets.NewApiGatewayv2DomainProperties(
			domain.RegionalDomainName(), domain.RegionalHostedZoneId(),
		)),
	})

	awscdk.NewCfnOutput(stack, jsii.String("IssuerUrl"), &awscdk.CfnOutputProps{
		Value: jsii.String("https://" + cfg.DomainName),
	})
	awscdk.NewCfnOutput(stack, jsii.String("TableNameOutput"), &awscdk.CfnOutputProps{
		Value: table.TableName(),
	})
	return stack
}
