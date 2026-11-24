.PHONY: test lint build-lambda cdk-synth cdk-diff cdk-deploy dev

test:
	go test ./...

lint:
	gofmt -l . | (! grep .)
	go vet ./...
	golangci-lint run ./...

# Lambda (ARM64, provided.al2023). CDK picks the binary up from dist/.
build-lambda:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/bootstrap ./cmd/cogin-lambda

cdk-synth: build-lambda
	cd infra && cdk synth --quiet

cdk-diff: build-lambda
	cd infra && cdk diff

cdk-deploy: test build-lambda
	cd infra && cdk deploy CoginStack

# Local server with an in-memory store (see cogin.example.json).
dev:
	COGIN_DEV=1 COGIN_CONFIG=cogin.json go run ./cmd/cogin
