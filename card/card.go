// Package card is the core of cogin: login cards (a QR code holding a
// high-entropy secret) protected by a PIN.
//
// A card is issued by a relying party (a "client") for one of its own users,
// identified by an opaque subject string the client chooses. Each subject has
// at most one valid card at a time. Re-issuing bumps the subject's generation,
// which invalidates the previous card in the same write, so "revoke the old QR
// and print a new one" is a single operation.
//
// The package has no HTTP or storage dependencies; storage is behind Store so
// the same rules apply whether cards live in DynamoDB or in memory.
package card

import (
	"time"
)

// Card is the stored state of a subject's login card. Secrets are never kept
// in plain text: only a hash of the token and a peppered hash of the PIN.
type Card struct {
	ClientID    string
	Subject     string
	DisplayName string

	// Generation increases on every issue and revoke. Relying parties can
	// compare it against the value in the ID token to drop sessions created
	// with an older card.
	Generation int64

	// CardID identifies the currently valid card. It is empty after a revoke
	// (the subject row is kept so the generation keeps increasing).
	CardID     string
	SecretHash []byte

	// PINHash is empty until the holder sets a PIN on first use.
	PINHash []byte

	// ActivateBy, when set, is the deadline for that first use. Cards sent
	// as a link (rather than handed over in person) get one: whoever opens
	// the link first sets the PIN, so an unused link must not stay usable
	// forever in a chat history.
	ActivateBy *time.Time

	// ExpiresAt, when set, ends the card's validity altogether (e.g. a card
	// for a three-day event). Unlike ActivateBy it applies after first use.
	ExpiresAt *time.Time

	FailedAttempts int
	LockedAt       *time.Time

	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastUsedAt *time.Time
}

// Active reports whether the subject currently has a usable card.
func (c *Card) Active() bool {
	return c.CardID != ""
}

// Locked reports whether the card is locked after too many wrong PINs.
func (c *Card) Locked() bool {
	return c.LockedAt != nil
}

// ActivationExpired reports whether the card was never used and its
// activation deadline has passed.
func (c *Card) ActivationExpired(now time.Time) bool {
	return !c.HasPIN() && c.ActivateBy != nil && now.After(*c.ActivateBy)
}

// Expired reports whether the card's validity period has ended.
func (c *Card) Expired(now time.Time) bool {
	return c.ExpiresAt != nil && !now.Before(*c.ExpiresAt)
}

// HasPIN reports whether the holder has already set a PIN.
func (c *Card) HasPIN() bool {
	return len(c.PINHash) > 0
}
