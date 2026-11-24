package dynamostore_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/yag13s/cogin/store/dynamostore"
	"github.com/yag13s/cogin/store/storetest"
)

// TestContract runs against DynamoDB Local when COGIN_TEST_DYNAMODB_ENDPOINT
// is set (e.g. http://localhost:8000). Each subtest gets its own throwaway
// table, deleted afterwards, so it is safe on a shared local instance.
func TestContract(t *testing.T) {
	endpoint := os.Getenv("COGIN_TEST_DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Skip("set COGIN_TEST_DYNAMODB_ENDPOINT to run against DynamoDB Local")
	}
	db := dynamodb.New(dynamodb.Options{
		Region:       "ap-northeast-1",
		BaseEndpoint: aws.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider("local", "local", ""),
	})
	storetest.Run(t, func(t *testing.T) storetest.Store {
		ctx := context.Background()
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		table := "cogin-test-" + hex.EncodeToString(b)
		_, err := db.CreateTable(ctx, &dynamodb.CreateTableInput{
			TableName: aws.String(table),
			AttributeDefinitions: []types.AttributeDefinition{
				{AttributeName: aws.String("PK"), AttributeType: types.ScalarAttributeTypeS},
				{AttributeName: aws.String("SK"), AttributeType: types.ScalarAttributeTypeS},
			},
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
			},
			BillingMode: types.BillingModePayPerRequest,
		})
		if err != nil {
			t.Fatalf("create table: %v", err)
		}
		t.Cleanup(func() {
			_, _ = db.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(table)})
		})
		return dynamostore.New(db, table)
	})
}
