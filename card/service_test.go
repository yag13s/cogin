package card_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yag13s/cogin/card"
	"github.com/yag13s/cogin/store/memstore"
)

var pepper = []byte("0123456789abcdef0123456789abcdef")

func newService(t *testing.T) *card.Service {
	t.Helper()
	s, err := card.NewService(memstore.New(), pepper)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func issueWithPIN(t *testing.T, s *card.Service, pin string) string {
	t.Helper()
	ctx := context.Background()
	tok, _, err := s.Issue(ctx, "app", "user-1", "たろう")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "app", tok, "", pin); err != nil {
		t.Fatalf("first use: %v", err)
	}
	return tok
}

func TestFirstUseRequiresPINSetup(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	tok, c, err := s.Issue(ctx, "app", "user-1", "たろう")
	if err != nil {
		t.Fatal(err)
	}
	if c.Generation != 1 || c.HasPIN() {
		t.Fatalf("new card = %+v", c)
	}
	if _, err := s.Authenticate(ctx, "app", tok, "1357", ""); !errors.Is(err, card.ErrPINSetupRequired) {
		t.Fatalf("err = %v, want ErrPINSetupRequired", err)
	}
	if _, err := s.Authenticate(ctx, "app", tok, "", "1234"); !errors.Is(err, card.ErrWeakPIN) {
		t.Fatalf("weak pin err = %v", err)
	}
	got, err := s.Authenticate(ctx, "app", tok, "", "3947")
	if err != nil || got.Subject != "user-1" {
		t.Fatalf("setup: %v %+v", err, got)
	}
	if _, err := s.Authenticate(ctx, "app", tok, "3947", ""); err != nil {
		t.Fatalf("login with set PIN: %v", err)
	}
}

func TestPINCannotBeClaimedTwice(t *testing.T) {
	s := newService(t)
	tok := issueWithPIN(t, s, "3947")
	// A second "first use" must not replace the PIN.
	if _, err := s.Authenticate(context.Background(), "app", tok, "", "9713"); !errors.Is(err, card.ErrPINRequired) {
		t.Fatalf("err = %v, want ErrPINRequired", err)
	}
}

func TestWrongPINLocks(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	tok := issueWithPIN(t, s, "3947")

	for i := card.DefaultMaxAttempts - 1; i >= 1; i-- {
		_, err := s.Authenticate(ctx, "app", tok, "0001", "")
		var wrong *card.WrongPINError
		if !errors.As(err, &wrong) || wrong.Remaining != i {
			t.Fatalf("attempt: err = %v, want %d remaining", err, i)
		}
	}
	if _, err := s.Authenticate(ctx, "app", tok, "0001", ""); !errors.Is(err, card.ErrLocked) {
		t.Fatalf("last attempt err = %v, want ErrLocked", err)
	}
	// Even the right PIN is refused once locked.
	if _, err := s.Authenticate(ctx, "app", tok, "3947", ""); !errors.Is(err, card.ErrLocked) {
		t.Fatalf("after lock err = %v, want ErrLocked", err)
	}
	if _, err := s.Unlock(ctx, "app", "user-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "app", tok, "3947", ""); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
}

func TestSuccessResetsFailures(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	tok := issueWithPIN(t, s, "3947")
	for range card.DefaultMaxAttempts - 1 {
		_, _ = s.Authenticate(ctx, "app", tok, "0001", "")
	}
	if _, err := s.Authenticate(ctx, "app", tok, "3947", ""); err != nil {
		t.Fatal(err)
	}
	_, err := s.Authenticate(ctx, "app", tok, "0001", "")
	var wrong *card.WrongPINError
	if !errors.As(err, &wrong) || wrong.Remaining != card.DefaultMaxAttempts-1 {
		t.Fatalf("err = %v, counter was not reset", err)
	}
}

func TestReissueInvalidatesOldCardAndPIN(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	old := issueWithPIN(t, s, "3947")

	tok, c, err := s.Issue(ctx, "app", "user-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Generation != 2 || c.HasPIN() || c.DisplayName != "たろう" {
		t.Fatalf("reissued = %+v", c)
	}
	if _, err := s.Authenticate(ctx, "app", old, "3947", ""); !errors.Is(err, card.ErrInvalidCard) {
		t.Fatalf("old card err = %v, want ErrInvalidCard", err)
	}
	if _, err := s.Authenticate(ctx, "app", tok, "3947", ""); !errors.Is(err, card.ErrPINSetupRequired) {
		t.Fatalf("new card err = %v, want ErrPINSetupRequired", err)
	}
}

func TestRevoke(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	tok := issueWithPIN(t, s, "3947")
	c, err := s.Revoke(ctx, "app", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Active() || c.Generation != 2 {
		t.Fatalf("revoked = %+v", c)
	}
	if _, err := s.Authenticate(ctx, "app", tok, "3947", ""); !errors.Is(err, card.ErrInvalidCard) {
		t.Fatalf("err = %v, want ErrInvalidCard", err)
	}
	if _, err := s.Revoke(ctx, "app", "nobody"); !errors.Is(err, card.ErrNotFound) {
		t.Fatalf("unknown subject err = %v", err)
	}
	// Issuing after a revoke keeps counting generations.
	_, c, err = s.Issue(ctx, "app", "user-1", "")
	if err != nil || c.Generation != 3 {
		t.Fatalf("issue after revoke: %v %+v", err, c)
	}
}

func TestCardIsBoundToItsClient(t *testing.T) {
	s := newService(t)
	tok := issueWithPIN(t, s, "3947")
	if _, err := s.Authenticate(context.Background(), "other-app", tok, "3947", ""); !errors.Is(err, card.ErrInvalidCard) {
		t.Fatalf("err = %v, want ErrInvalidCard", err)
	}
}

func TestTamperedTokens(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	tok := issueWithPIN(t, s, "3947")
	for _, bad := range []string{
		"",
		"garbage",
		tok[:len(tok)-1] + "A",   // wrong secret, right card id
		"cgc_zzzzzzzzzzzzzzzz_x", // non-hex id
		"cgc_0000000000000000_x", // unknown id
	} {
		if _, err := s.Authenticate(ctx, "app", bad, "3947", ""); !errors.Is(err, card.ErrInvalidCard) {
			t.Errorf("token %q: err = %v, want ErrInvalidCard", bad, err)
		}
	}
	// A wrong secret must not count towards the lock of the real card.
	if _, err := s.Authenticate(ctx, "app", tok, "3947", ""); err != nil {
		t.Fatal(err)
	}
	c, _ := s.Get(ctx, "app", "user-1")
	if c.FailedAttempts != 0 {
		t.Fatalf("failed attempts = %d", c.FailedAttempts)
	}
}

func TestWeakPINs(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	for _, pin := range []string{
		"123", "123456789", "abcd", "12 34", // shape
		"0000", "1234", "9876", "1212", "123123", "1122", "112233", "1221", // patterns
		"1987", "2001", "2580", "1379", "5683", "1004", "147258", // years, keypad, common
	} {
		tok, _, err := s.Issue(ctx, "app", "u", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Authenticate(ctx, "app", tok, "", pin); !errors.Is(err, card.ErrWeakPIN) {
			t.Errorf("pin %q: err = %v, want ErrWeakPIN", pin, err)
		}
	}
}

func TestActivationDeadline(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	s, err := card.NewService(memstore.New(), pepper, card.WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	tok, c, err := s.Issue(ctx, "app", "u", "", card.IssueOptions{ActivateWithin: 24 * time.Hour})
	if err != nil || c.ActivateBy == nil || !c.ActivateBy.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("issue: %v %+v", err, c)
	}
	now = now.Add(25 * time.Hour)
	if _, err := s.Authenticate(ctx, "app", tok, "", "3947"); !errors.Is(err, card.ErrActivationExpired) {
		t.Fatalf("expired link err = %v", err)
	}
	if _, err := s.Authenticate(ctx, "app", tok, "", ""); !errors.Is(err, card.ErrActivationExpired) {
		t.Fatalf("expired link without PIN err = %v, want the expiry before the PIN prompt", err)
	}

	// Used in time: the deadline no longer matters afterwards.
	tok, _, _ = s.Issue(ctx, "app", "u", "", card.IssueOptions{ActivateWithin: time.Hour})
	if _, err := s.Authenticate(ctx, "app", tok, "", "3947"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(48 * time.Hour)
	if _, err := s.Authenticate(ctx, "app", tok, "3947", ""); err != nil {
		t.Fatalf("login long after activation: %v", err)
	}

	// No deadline by default (printed cards handed over in person).
	tok, c, _ = s.Issue(ctx, "app", "u", "")
	if c.ActivateBy != nil {
		t.Fatalf("default card has a deadline: %v", c.ActivateBy)
	}
	now = now.Add(365 * 24 * time.Hour)
	if _, err := s.Authenticate(ctx, "app", tok, "", "3947"); err != nil {
		t.Fatalf("printed card after a year: %v", err)
	}
}

func TestCardExpiry(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	s, err := card.NewService(memstore.New(), pepper, card.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	tok, c, err := s.Issue(ctx, "app", "u", "", card.IssueOptions{ExpiresIn: 72 * time.Hour})
	if err != nil || c.ExpiresAt == nil || !c.ExpiresAt.Equal(now.Add(72*time.Hour)) {
		t.Fatalf("issue: %v %+v", err, c)
	}
	if _, err := s.Authenticate(ctx, "app", tok, "", "3947"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(71 * time.Hour)
	if _, err := s.Authenticate(ctx, "app", tok, "3947", ""); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	now = now.Add(time.Hour)
	if _, err := s.Authenticate(ctx, "app", tok, "3947", ""); !errors.Is(err, card.ErrCardExpired) {
		t.Fatalf("at expiry: %v, want ErrCardExpired", err)
	}
	if _, err := s.Resolve(ctx, tok); !errors.Is(err, card.ErrCardExpired) {
		t.Fatalf("resolve after expiry: %v", err)
	}
	// Wrong PINs on an expired card do not count towards a lock.
	for range card.DefaultMaxAttempts + 1 {
		_, _ = s.Authenticate(ctx, "app", tok, "0001", "")
	}
	got, _ := s.Get(ctx, "app", "u")
	if got.FailedAttempts != 0 || got.Locked() {
		t.Fatalf("expired card collected failures: %+v", got)
	}
	// Re-issuing starts a fresh card; without ExpiresIn it never expires.
	tok, c, _ = s.Issue(ctx, "app", "u", "")
	if c.ExpiresAt != nil {
		t.Fatalf("re-issued card kept expiry %v", c.ExpiresAt)
	}
	if _, err := s.Authenticate(ctx, "app", tok, "", "3947"); err != nil {
		t.Fatal(err)
	}
}

func TestOrdinaryPINsAreAccepted(t *testing.T) {
	s := newService(t)
	ctx := context.Background()
	for _, pin := range []string{"3947", "8261", "48213", "730194", "50418362"} {
		tok, _, err := s.Issue(ctx, "app", "u", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Authenticate(ctx, "app", tok, "", pin); err != nil {
			t.Errorf("pin %q rejected: %v", pin, err)
		}
	}
}
