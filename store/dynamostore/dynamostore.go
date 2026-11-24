// Package dynamostore implements the cogin stores on a single DynamoDB table
// with string keys PK/SK and a TTL attribute "ttl".
//
//	card     PK=CLIENT#{clientID}  SK=CARD#{subject}
//	index    PK=CARDID#{cardID}    SK=INFO
//	code     PK=CODE#{hash}        SK=INFO        (ttl)
package dynamostore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/yag13s/cogin/card"
	"github.com/yag13s/cogin/oidc"
)

// Store implements card.Store and oidc.CodeStore.
type Store struct {
	db    *dynamodb.Client
	table string
}

// New returns a Store on the given table.
func New(db *dynamodb.Client, table string) *Store {
	return &Store{db: db, table: table}
}

type cardItem struct {
	PK             string     `dynamodbav:"PK"`
	SK             string     `dynamodbav:"SK"`
	ClientID       string     `dynamodbav:"clientId"`
	Subject        string     `dynamodbav:"subject"`
	DisplayName    string     `dynamodbav:"displayName,omitempty"`
	Generation     int64      `dynamodbav:"generation"`
	CardID         string     `dynamodbav:"cardId,omitempty"`
	SecretHash     []byte     `dynamodbav:"secretHash,omitempty"`
	PINHash        []byte     `dynamodbav:"pinHash,omitempty"`
	ActivateBy     *time.Time `dynamodbav:"activateBy,omitempty"`
	ExpiresAt      *time.Time `dynamodbav:"expiresAt,omitempty"`
	FailedAttempts int        `dynamodbav:"failedAttempts"`
	LockedAt       *time.Time `dynamodbav:"lockedAt,omitempty"`
	CreatedAt      time.Time  `dynamodbav:"createdAt"`
	UpdatedAt      time.Time  `dynamodbav:"updatedAt"`
	LastUsedAt     *time.Time `dynamodbav:"lastUsedAt,omitempty"`
}

func cardKey(clientID, subject string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: "CLIENT#" + clientID},
		"SK": &types.AttributeValueMemberS{Value: "CARD#" + subject},
	}
}

func singleKey(pk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: pk},
		"SK": &types.AttributeValueMemberS{Value: "INFO"},
	}
}

func toCard(it *cardItem) *card.Card {
	return &card.Card{
		ClientID:       it.ClientID,
		Subject:        it.Subject,
		DisplayName:    it.DisplayName,
		Generation:     it.Generation,
		CardID:         it.CardID,
		SecretHash:     it.SecretHash,
		PINHash:        it.PINHash,
		ActivateBy:     it.ActivateBy,
		ExpiresAt:      it.ExpiresAt,
		FailedAttempts: it.FailedAttempts,
		LockedAt:       it.LockedAt,
		CreatedAt:      it.CreatedAt,
		UpdatedAt:      it.UpdatedAt,
		LastUsedAt:     it.LastUsedAt,
	}
}

func isConditionFailed(err error) bool {
	var ccf *types.ConditionalCheckFailedException
	return errors.As(err, &ccf)
}

func avS(s string) types.AttributeValue { return &types.AttributeValueMemberS{Value: s} }

func avN(n int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(n, 10)}
}

func avTime(t time.Time) types.AttributeValue {
	v, _ := attributevalue.Marshal(t)
	return v
}

// Get implements card.Store.
func (s *Store) Get(ctx context.Context, clientID, subject string) (*card.Card, error) {
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            cardKey(clientID, subject),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("get card: %w", err)
	}
	if out.Item == nil {
		return nil, nil
	}
	var it cardItem
	if err := attributevalue.UnmarshalMap(out.Item, &it); err != nil {
		return nil, err
	}
	return toCard(&it), nil
}

// Put implements card.Store.
func (s *Store) Put(ctx context.Context, c *card.Card, prevGen int64) error {
	it := cardItem{
		PK: "CLIENT#" + c.ClientID, SK: "CARD#" + c.Subject,
		ClientID: c.ClientID, Subject: c.Subject, DisplayName: c.DisplayName,
		Generation: c.Generation, CardID: c.CardID, SecretHash: c.SecretHash, PINHash: c.PINHash, ActivateBy: c.ActivateBy, ExpiresAt: c.ExpiresAt,
		FailedAttempts: c.FailedAttempts, LockedAt: c.LockedAt,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt, LastUsedAt: c.LastUsedAt,
	}
	item, err := attributevalue.MarshalMap(it)
	if err != nil {
		return err
	}
	in := &dynamodb.PutItemInput{TableName: aws.String(s.table), Item: item}
	if prevGen == 0 {
		in.ConditionExpression = aws.String("attribute_not_exists(PK)")
	} else {
		in.ConditionExpression = aws.String("generation = :g")
		in.ExpressionAttributeValues = map[string]types.AttributeValue{":g": avN(prevGen)}
	}
	if _, err := s.db.PutItem(ctx, in); err != nil {
		if isConditionFailed(err) {
			return card.ErrConflict
		}
		return fmt.Errorf("put card: %w", err)
	}
	return nil
}

// List implements card.Store.
func (s *Store) List(ctx context.Context, clientID string) ([]*card.Card, error) {
	p := dynamodb.NewQueryPaginator(s.db, &dynamodb.QueryInput{
		TableName:              aws.String(s.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :sk)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS("CLIENT#" + clientID),
			":sk": avS("CARD#"),
		},
	})
	var out []*card.Card
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list cards: %w", err)
		}
		var items []cardItem
		if err := attributevalue.UnmarshalListOfMaps(page.Items, &items); err != nil {
			return nil, err
		}
		for i := range items {
			out = append(out, toCard(&items[i]))
		}
	}
	return out, nil
}

// PutIndex implements card.Store.
func (s *Store) PutIndex(ctx context.Context, cardID, clientID, subject string) error {
	item := singleKey("CARDID#" + cardID)
	item["clientId"] = avS(clientID)
	item["subject"] = avS(subject)
	_, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(s.table), Item: item})
	if err != nil {
		return fmt.Errorf("put card index: %w", err)
	}
	return nil
}

// Lookup implements card.Store.
func (s *Store) Lookup(ctx context.Context, cardID string) (string, string, bool, error) {
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.table),
		Key:       singleKey("CARDID#" + cardID),
	})
	if err != nil {
		return "", "", false, fmt.Errorf("lookup card: %w", err)
	}
	if out.Item == nil {
		return "", "", false, nil
	}
	var v struct {
		ClientID string `dynamodbav:"clientId"`
		Subject  string `dynamodbav:"subject"`
	}
	if err := attributevalue.UnmarshalMap(out.Item, &v); err != nil {
		return "", "", false, err
	}
	return v.ClientID, v.Subject, true, nil
}

// DeleteIndex implements card.Store.
func (s *Store) DeleteIndex(ctx context.Context, cardID string) error {
	_, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.table),
		Key:       singleKey("CARDID#" + cardID),
	})
	return err
}

// belowLimit is the condition shared by RecordFailure and RecordSuccess: the
// card is still the one with :cid, not locked, and has fewer than :max
// failures. Checking the count (not only lockedAt) closes the window between
// the increment that reaches the limit and the write that sets lockedAt, so
// a burst of concurrent PINs gets at most maxAttempts tries in total.
const belowLimit = "cardId = :cid AND attribute_not_exists(lockedAt) AND " +
	"(attribute_not_exists(failedAttempts) OR failedAttempts < :max)"

// RecordFailure implements card.Store.
func (s *Store) RecordFailure(ctx context.Context, clientID, subject, cardID string, maxAttempts int, now time.Time) (*card.Card, error) {
	out, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.table),
		Key:                 cardKey(clientID, subject),
		UpdateExpression:    aws.String("ADD failedAttempts :one SET updatedAt = :now"),
		ConditionExpression: aws.String(belowLimit),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one": avN(1),
			":now": avTime(now),
			":cid": avS(cardID),
			":max": avN(int64(maxAttempts)),
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if err != nil {
		if isConditionFailed(err) {
			return nil, card.ErrConflict
		}
		return nil, fmt.Errorf("record failure: %w", err)
	}
	var it cardItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &it); err != nil {
		return nil, err
	}
	if it.FailedAttempts >= maxAttempts {
		_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName:           aws.String(s.table),
			Key:                 cardKey(clientID, subject),
			UpdateExpression:    aws.String("SET lockedAt = :now"),
			ConditionExpression: aws.String("cardId = :cid AND attribute_not_exists(lockedAt)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":now": avTime(now),
				":cid": avS(cardID),
			},
		})
		if err != nil && !isConditionFailed(err) {
			return nil, fmt.Errorf("lock card: %w", err)
		}
		t := now
		it.LockedAt = &t
	}
	return toCard(&it), nil
}

// RecordSuccess implements card.Store.
func (s *Store) RecordSuccess(ctx context.Context, clientID, subject, cardID string, maxAttempts int, now time.Time) error {
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.table),
		Key:                 cardKey(clientID, subject),
		UpdateExpression:    aws.String("SET failedAttempts = :zero, lastUsedAt = :now"),
		ConditionExpression: aws.String(belowLimit),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":zero": avN(0),
			":now":  avTime(now),
			":cid":  avS(cardID),
			":max":  avN(int64(maxAttempts)),
		},
	})
	if err != nil {
		if isConditionFailed(err) {
			return card.ErrConflict
		}
		return fmt.Errorf("record success: %w", err)
	}
	return nil
}

// SetPIN implements card.Store.
func (s *Store) SetPIN(ctx context.Context, clientID, subject, cardID string, pinHash []byte, now time.Time) error {
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.table),
		Key:                 cardKey(clientID, subject),
		UpdateExpression:    aws.String("SET pinHash = :pin, updatedAt = :now, lastUsedAt = :now"),
		ConditionExpression: aws.String("cardId = :cid AND attribute_not_exists(pinHash)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pin": &types.AttributeValueMemberB{Value: pinHash},
			":now": avTime(now),
			":cid": avS(cardID),
		},
	})
	if err != nil {
		if isConditionFailed(err) {
			return card.ErrConflict
		}
		return fmt.Errorf("set pin: %w", err)
	}
	return nil
}

// Unlock implements card.Store.
func (s *Store) Unlock(ctx context.Context, clientID, subject string, now time.Time) error {
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:           aws.String(s.table),
		Key:                 cardKey(clientID, subject),
		UpdateExpression:    aws.String("SET failedAttempts = :zero, updatedAt = :now REMOVE lockedAt"),
		ConditionExpression: aws.String("attribute_exists(PK)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":zero": avN(0),
			":now":  avTime(now),
		},
	})
	if err != nil {
		if isConditionFailed(err) {
			return card.ErrNotFound
		}
		return fmt.Errorf("unlock: %w", err)
	}
	return nil
}

type codeItem struct {
	PK string `dynamodbav:"PK"`
	SK string `dynamodbav:"SK"`
	oidc.AuthCode
	Expires int64 `dynamodbav:"expires"`
	TTL     int64 `dynamodbav:"ttl"`
}

// PutCode implements oidc.CodeStore.
func (s *Store) PutCode(ctx context.Context, hash string, code *oidc.AuthCode, ttl time.Duration) error {
	exp := time.Now().Add(ttl)
	item, err := attributevalue.MarshalMap(codeItem{
		PK: "CODE#" + hash, SK: "INFO", AuthCode: *code,
		Expires: exp.Unix(),
		// DynamoDB TTL deletes lazily (up to days late), so expiry is also
		// checked in ConsumeCode; ttl only keeps the table tidy.
		TTL: exp.Add(time.Hour).Unix(),
	})
	if err != nil {
		return err
	}
	_, err = s.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(s.table), Item: item})
	return err
}

// ConsumeCode implements oidc.CodeStore with a single DeleteItem returning
// the old item, so two concurrent redemptions cannot both succeed.
func (s *Store) ConsumeCode(ctx context.Context, hash string) (*oidc.AuthCode, error) {
	out, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:    aws.String(s.table),
		Key:          singleKey("CODE#" + hash),
		ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		return nil, fmt.Errorf("consume code: %w", err)
	}
	if out.Attributes == nil {
		return nil, nil
	}
	var it codeItem
	if err := attributevalue.UnmarshalMap(out.Attributes, &it); err != nil {
		return nil, err
	}
	if time.Now().Unix() > it.Expires {
		return nil, nil
	}
	return &it.AuthCode, nil
}
