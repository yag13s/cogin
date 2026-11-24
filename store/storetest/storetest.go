// Package storetest is a contract test suite that every cogin store
// implementation must pass, so the in-memory store used in tests cannot drift
// from the DynamoDB one used in production.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yag13s/cogin/card"
	"github.com/yag13s/cogin/oidc"
)

// Store is what a cogin backend implements.
type Store interface {
	card.Store
	oidc.CodeStore
}

// Run runs the suite. newStore must return an empty store per call.
func Run(t *testing.T, newStore func(t *testing.T) Store) {
	ctx := context.Background()
	pepper := []byte("0123456789abcdef0123456789abcdef")

	t.Run("lifecycle through card.Service", func(t *testing.T) {
		st := newStore(t)
		svc, err := card.NewService(st, pepper, card.WithMaxAttempts(3))
		if err != nil {
			t.Fatal(err)
		}
		tok, c, err := svc.Issue(ctx, "app", "s/1", "名前")
		if err != nil || c.Generation != 1 {
			t.Fatalf("issue: %v %+v", err, c)
		}
		if _, err := svc.Authenticate(ctx, "app", tok, "", "3947"); err != nil {
			t.Fatalf("setup: %v", err)
		}
		got, err := svc.Get(ctx, "app", "s/1")
		if err != nil || !got.HasPIN() || got.LastUsedAt == nil || got.DisplayName != "名前" {
			t.Fatalf("after setup: %v %+v", err, got)
		}
		for range 2 {
			_, _ = svc.Authenticate(ctx, "app", tok, "0001", "")
		}
		if _, err := svc.Authenticate(ctx, "app", tok, "0001", ""); !errors.Is(err, card.ErrLocked) {
			t.Fatalf("lock: %v", err)
		}
		if _, err := svc.Unlock(ctx, "app", "s/1"); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Authenticate(ctx, "app", tok, "3947", ""); err != nil {
			t.Fatalf("after unlock: %v", err)
		}
		tok2, c, err := svc.Issue(ctx, "app", "s/1", "")
		if err != nil || c.Generation != 2 {
			t.Fatalf("reissue: %v %+v", err, c)
		}
		if _, err := svc.Authenticate(ctx, "app", tok, "3947", ""); !errors.Is(err, card.ErrInvalidCard) {
			t.Fatalf("old card: %v", err)
		}
		if _, _, found, _ := st.Lookup(ctx, mustCardID(t, tok)); found {
			t.Error("old index was not cleaned up")
		}
		if _, err := svc.Revoke(ctx, "app", "s/1"); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Authenticate(ctx, "app", tok2, "", "3947"); !errors.Is(err, card.ErrInvalidCard) {
			t.Fatalf("revoked card: %v", err)
		}
		list, err := svc.List(ctx, "app")
		if err != nil || len(list) != 1 || list[0].Generation != 3 {
			t.Fatalf("list: %v %+v", err, list)
		}
		if list, _ := svc.List(ctx, "other"); len(list) != 0 {
			t.Fatalf("other client sees %d cards", len(list))
		}
	})

	t.Run("activation deadline and expiry round-trip", func(t *testing.T) {
		st := newStore(t)
		svc, err := card.NewService(st, pepper)
		if err != nil {
			t.Fatal(err)
		}
		_, c, err := svc.Issue(ctx, "app", "s", "", card.IssueOptions{ActivateWithin: time.Hour, ExpiresIn: 48 * time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		got, err := svc.Get(ctx, "app", "s")
		if err != nil || got.ActivateBy == nil || !got.ActivateBy.Equal(*c.ActivateBy) {
			t.Fatalf("activateBy = %v, want %v (err %v)", got.ActivateBy, c.ActivateBy, err)
		}
		if got.ExpiresAt == nil || !got.ExpiresAt.Equal(*c.ExpiresAt) {
			t.Fatalf("expiresAt = %v, want %v", got.ExpiresAt, c.ExpiresAt)
		}
		revoked, err := svc.Revoke(ctx, "app", "s")
		if err != nil || revoked.ActivateBy != nil || revoked.ExpiresAt != nil {
			t.Fatalf("revoke kept the deadline: %v %v", revoked.ActivateBy, err)
		}
	})

	t.Run("conditional writes", func(t *testing.T) {
		st := newStore(t)
		now := time.Now().UTC().Truncate(time.Millisecond)
		c := &card.Card{ClientID: "app", Subject: "s", Generation: 1, CardID: "aaaa", CreatedAt: now, UpdatedAt: now}
		if err := st.Put(ctx, c, 0); err != nil {
			t.Fatal(err)
		}
		if err := st.Put(ctx, c, 0); !errors.Is(err, card.ErrConflict) {
			t.Fatalf("create twice: %v", err)
		}
		c2 := *c
		c2.Generation = 2
		if err := st.Put(ctx, &c2, 5); !errors.Is(err, card.ErrConflict) {
			t.Fatalf("stale generation: %v", err)
		}
		if err := st.Put(ctx, &c2, 1); err != nil {
			t.Fatal(err)
		}
		if err := st.SetPIN(ctx, "app", "s", "bbbb", []byte{1}, now); !errors.Is(err, card.ErrConflict) {
			t.Fatalf("set pin on other card id: %v", err)
		}
		if err := st.SetPIN(ctx, "app", "s", "aaaa", []byte{1}, now); err != nil {
			t.Fatal(err)
		}
		if err := st.SetPIN(ctx, "app", "s", "aaaa", []byte{2}, now); !errors.Is(err, card.ErrConflict) {
			t.Fatalf("set pin twice: %v", err)
		}
		if _, err := st.RecordFailure(ctx, "app", "s", "bbbb", 3, now); !errors.Is(err, card.ErrConflict) {
			t.Fatalf("failure on other card id: %v", err)
		}
		if err := st.RecordSuccess(ctx, "app", "s", "bbbb", 3, now); !errors.Is(err, card.ErrConflict) {
			t.Fatalf("success on other card id: %v", err)
		}
		if err := st.Unlock(ctx, "app", "missing", now); err == nil {
			t.Fatal("unlock of missing subject succeeded")
		}
	})

	t.Run("limit holds before the lock is written", func(t *testing.T) {
		// The state between the increment that reaches the limit and the
		// write that sets lockedAt: concurrent requests must already be
		// refused here, or a burst of PINs gets more than maxAttempts tries.
		st := newStore(t)
		now := time.Now().UTC().Truncate(time.Millisecond)
		c := &card.Card{ClientID: "app", Subject: "s", Generation: 1, CardID: "aaaa", PINHash: []byte{1},
			FailedAttempts: 3, CreatedAt: now, UpdatedAt: now}
		if err := st.Put(ctx, c, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := st.RecordFailure(ctx, "app", "s", "aaaa", 3, now); !errors.Is(err, card.ErrConflict) {
			t.Fatalf("failure past the limit: %v", err)
		}
		if err := st.RecordSuccess(ctx, "app", "s", "aaaa", 3, now); !errors.Is(err, card.ErrConflict) {
			t.Fatalf("success past the limit: %v", err)
		}
		if err := st.Unlock(ctx, "app", "s", now); err != nil {
			t.Fatal(err)
		}
		if err := st.RecordSuccess(ctx, "app", "s", "aaaa", 3, now); err != nil {
			t.Fatalf("success after unlock: %v", err)
		}
	})

	t.Run("codes are single use", func(t *testing.T) {
		st := newStore(t)
		exp := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		code := &oidc.AuthCode{ClientID: "app", Subject: "s", Generation: 4, CardExpiresAt: &exp, AuthTime: time.Now().UTC().Truncate(time.Second)}
		if err := st.PutCode(ctx, "h1", code, time.Minute); err != nil {
			t.Fatal(err)
		}
		got, err := st.ConsumeCode(ctx, "h1")
		if err != nil || got == nil || got.Subject != "s" || got.Generation != 4 || !got.AuthTime.Equal(code.AuthTime) ||
			got.CardExpiresAt == nil || !got.CardExpiresAt.Equal(exp) {
			t.Fatalf("consume: %v %+v", err, got)
		}
		if got, _ := st.ConsumeCode(ctx, "h1"); got != nil {
			t.Fatal("code consumed twice")
		}
		if err := st.PutCode(ctx, "h2", code, -time.Second); err != nil {
			t.Fatal(err)
		}
		if got, _ := st.ConsumeCode(ctx, "h2"); got != nil {
			t.Fatal("expired code accepted")
		}
	})
}

func mustCardID(t *testing.T, token string) string {
	t.Helper()
	// cgc_{16 hex}_{secret}
	if len(token) < 4+16 {
		t.Fatalf("token %q", token)
	}
	return token[4 : 4+16]
}
