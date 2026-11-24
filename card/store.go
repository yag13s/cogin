package card

import (
	"context"
	"errors"
	"time"
)

// ErrConflict is returned by Store writes whose precondition no longer holds
// (another request changed the card first).
var ErrConflict = errors.New("card: concurrent update")

// Store persists cards. Every write that depends on the current state is
// conditional, because two requests for the same card can race (two shared
// terminals trying PINs at once, an admin re-issuing during a login).
type Store interface {
	// Get returns the subject's card, or nil if the subject has never had one.
	Get(ctx context.Context, clientID, subject string) (*Card, error)

	// Put writes c only if the stored generation is prevGen (0 means the
	// subject must not exist yet). Otherwise it returns ErrConflict.
	Put(ctx context.Context, c *Card, prevGen int64) error

	// List returns all cards of a client.
	List(ctx context.Context, clientID string) ([]*Card, error)

	// PutIndex maps a card id to its subject so a scanned token can be
	// resolved without knowing who it belongs to.
	PutIndex(ctx context.Context, cardID, clientID, subject string) error

	// Lookup resolves a card id. found is false for unknown ids.
	Lookup(ctx context.Context, cardID string) (clientID, subject string, found bool, err error)

	// DeleteIndex removes a card id mapping. Stale mappings are harmless
	// (the card id no longer matches the subject row), so callers treat this
	// as best-effort cleanup.
	DeleteIndex(ctx context.Context, cardID string) error

	// RecordFailure adds one failed attempt to the card if it is still the
	// card with cardID, not locked and below maxAttempts failures, and locks
	// it once the count reaches maxAttempts. It returns the updated card, or
	// ErrConflict if the card changed or the limit is already reached.
	RecordFailure(ctx context.Context, clientID, subject, cardID string, maxAttempts int, now time.Time) (*Card, error)

	// RecordSuccess resets the failure count and stamps the last use, if the
	// card is still the card with cardID, not locked and below maxAttempts
	// failures. Otherwise it returns ErrConflict: a correct PIN that arrives
	// after concurrent wrong ones used up the attempts must not log in.
	RecordSuccess(ctx context.Context, clientID, subject, cardID string, maxAttempts int, now time.Time) error

	// SetPIN stores the first PIN of the card with cardID. It returns
	// ErrConflict if a PIN is already set, so two people racing to claim a
	// fresh card cannot overwrite each other.
	SetPIN(ctx context.Context, clientID, subject, cardID string, pinHash []byte, now time.Time) error

	// Unlock clears the lock and the failure count.
	Unlock(ctx context.Context, clientID, subject string, now time.Time) error
}
