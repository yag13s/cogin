package card

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"
)

// Errors returned by Service. Authentication failures that would tell an
// attacker something about a card they do not hold are all ErrInvalidCard.
var (
	ErrInvalidCard       = errors.New("card: invalid or revoked card")
	ErrLocked            = errors.New("card: locked after too many wrong PINs")
	ErrPINRequired       = errors.New("card: PIN required")
	ErrPINSetupRequired  = errors.New("card: PIN not set yet")
	ErrWeakPIN           = errors.New("card: PIN must be 4-8 digits and not a trivial pattern")
	ErrNotFound          = errors.New("card: subject not found")
	ErrInvalidSubject    = errors.New("card: subject must be 1-256 bytes")
	ErrActivationExpired = errors.New("card: the card was not used before its activation deadline")
	ErrCardExpired       = errors.New("card: the card's validity period has ended")
)

// WrongPINError reports a wrong PIN and how many attempts remain before the
// card locks. Showing the count is deliberate: the holder needs it to stop
// before locking themselves out, and an attacker already knows the limit.
type WrongPINError struct {
	Remaining int
}

func (e *WrongPINError) Error() string {
	return fmt.Sprintf("card: wrong PIN (%d attempts left)", e.Remaining)
}

// DefaultMaxAttempts is the number of wrong PINs that locks a card. Kept low
// because the guesses that matter are the few most common PINs; every extra
// attempt is one more of them.
const DefaultMaxAttempts = 3

const maxSubjectLength = 256

// Service implements issuing, revoking and authenticating cards.
type Service struct {
	store       Store
	pepper      []byte
	maxAttempts int
	now         func() time.Time
}

// Option configures a Service.
type Option func(*Service)

// WithMaxAttempts overrides DefaultMaxAttempts.
func WithMaxAttempts(n int) Option {
	return func(s *Service) { s.maxAttempts = n }
}

// WithClock overrides time.Now (for tests).
func WithClock(now func() time.Time) Option {
	return func(s *Service) { s.now = now }
}

// NewService returns a Service. pepper must be a secret of at least 32 bytes
// kept outside the store; see hashPIN for why.
func NewService(store Store, pepper []byte, opts ...Option) (*Service, error) {
	if len(pepper) < 32 {
		return nil, errors.New("card: pepper must be at least 32 bytes")
	}
	s := &Service{store: store, pepper: pepper, maxAttempts: DefaultMaxAttempts, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// MaxAttempts returns the number of wrong PINs that locks a card.
func (s *Service) MaxAttempts() int { return s.maxAttempts }

// IssueOptions are optional settings for Issue.
type IssueOptions struct {
	// ActivateWithin, when positive, limits how long the card can wait for
	// its first use (PIN setup). Meant for cards sent as a link.
	ActivateWithin time.Duration
	// ExpiresIn, when positive, ends the card's validity that long after
	// issuing, whether or not it has been used.
	ExpiresIn time.Duration
}

// Issue creates a new card for the subject, invalidating any previous one.
// The new card has no PIN: a lost card may have been seen together with its
// PIN, so re-issuing always starts over. The token is returned only here.
func (s *Service) Issue(ctx context.Context, clientID, subject, displayName string, opts ...IssueOptions) (string, *Card, error) {
	var opt IssueOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	if err := validSubject(subject); err != nil {
		return "", nil, err
	}
	for range 3 {
		cur, err := s.store.Get(ctx, clientID, subject)
		if err != nil {
			return "", nil, err
		}
		cardID, token, err := newToken()
		if err != nil {
			return "", nil, err
		}
		now := s.now().UTC()
		next := &Card{
			ClientID:    clientID,
			Subject:     subject,
			DisplayName: displayName,
			Generation:  1,
			CardID:      cardID,
			SecretHash:  hashToken(token),
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if opt.ActivateWithin > 0 {
			by := now.Add(opt.ActivateWithin)
			next.ActivateBy = &by
		}
		if opt.ExpiresIn > 0 {
			exp := now.Add(opt.ExpiresIn)
			next.ExpiresAt = &exp
		}
		var prevGen int64
		if cur != nil {
			prevGen = cur.Generation
			next.Generation = cur.Generation + 1
			if displayName == "" {
				next.DisplayName = cur.DisplayName
			}
		}
		// The index goes first: if Put then fails, the orphan index points at
		// a card id the subject row never had, which Authenticate rejects.
		if err := s.store.PutIndex(ctx, cardID, clientID, subject); err != nil {
			return "", nil, err
		}
		err = s.store.Put(ctx, next, prevGen)
		if errors.Is(err, ErrConflict) {
			_ = s.store.DeleteIndex(ctx, cardID)
			continue
		}
		if err != nil {
			return "", nil, err
		}
		if cur != nil && cur.CardID != "" {
			_ = s.store.DeleteIndex(ctx, cur.CardID)
		}
		return token, next, nil
	}
	return "", nil, ErrConflict
}

// Revoke invalidates the subject's card without issuing a new one.
func (s *Service) Revoke(ctx context.Context, clientID, subject string) (*Card, error) {
	for range 3 {
		cur, err := s.store.Get(ctx, clientID, subject)
		if err != nil {
			return nil, err
		}
		if cur == nil {
			return nil, ErrNotFound
		}
		next := *cur
		next.Generation++
		next.CardID = ""
		next.SecretHash = nil
		next.PINHash = nil
		next.ActivateBy = nil
		next.ExpiresAt = nil
		next.FailedAttempts = 0
		next.LockedAt = nil
		next.UpdatedAt = s.now().UTC()
		err = s.store.Put(ctx, &next, cur.Generation)
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if cur.CardID != "" {
			_ = s.store.DeleteIndex(ctx, cur.CardID)
		}
		return &next, nil
	}
	return nil, ErrConflict
}

// Unlock clears a lock without changing the card, for when the holder just
// mistyped and the admin is sure the card was not stolen.
func (s *Service) Unlock(ctx context.Context, clientID, subject string) (*Card, error) {
	cur, err := s.store.Get(ctx, clientID, subject)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, ErrNotFound
	}
	if err := s.store.Unlock(ctx, clientID, subject, s.now().UTC()); err != nil {
		return nil, err
	}
	return s.store.Get(ctx, clientID, subject)
}

// Get returns the subject's card, or ErrNotFound.
func (s *Service) Get(ctx context.Context, clientID, subject string) (*Card, error) {
	c, err := s.store.Get(ctx, clientID, subject)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, ErrNotFound
	}
	return c, nil
}

// List returns all cards of a client.
func (s *Service) List(ctx context.Context, clientID string) ([]*Card, error) {
	return s.store.List(ctx, clientID)
}

// Resolve checks a token without a PIN and returns its card. It is used to
// route a scanned card to the right client before the login starts; it does
// not authenticate anyone, so it neither counts nor resets failures.
func (s *Service) Resolve(ctx context.Context, token string) (*Card, error) {
	c, err := s.lookup(ctx, token)
	if err != nil {
		return nil, err
	}
	if c.Expired(s.now()) {
		return nil, ErrCardExpired
	}
	return c, nil
}

// Authenticate checks a scanned token and PIN for clientID.
//
// On a card without a PIN, newPIN sets it (first use) and the login succeeds;
// without newPIN it returns ErrPINSetupRequired so the UI can ask for one.
// Only wrong PINs count towards the lock: a wrong token cannot be attributed
// to any card, and with 256 random bits it cannot be guessed either.
func (s *Service) Authenticate(ctx context.Context, clientID, token, pin, newPIN string) (*Card, error) {
	c, err := s.lookup(ctx, token)
	if err != nil {
		return nil, err
	}
	// A card is only good for the client that issued it; otherwise a card for
	// one service would log its holder into another.
	if c.ClientID != clientID {
		return nil, ErrInvalidCard
	}
	now := s.now().UTC()
	// Expiry is checked first: an expired card is over regardless of its
	// PIN, and wrong PINs on it must not count towards a lock.
	if c.Expired(now) {
		return nil, ErrCardExpired
	}
	if c.Locked() {
		return nil, ErrLocked
	}

	if !c.HasPIN() {
		// Checked before asking for a PIN so an expired link fails right
		// away instead of after the holder picked one.
		if c.ActivationExpired(now) {
			return nil, ErrActivationExpired
		}
		if newPIN == "" {
			return nil, ErrPINSetupRequired
		}
		if err := validatePIN(newPIN); err != nil {
			return nil, err
		}
		h := hashPIN(s.pepper, c.CardID, newPIN)
		if err := s.store.SetPIN(ctx, c.ClientID, c.Subject, c.CardID, h, now); err != nil {
			if errors.Is(err, ErrConflict) {
				// Someone else claimed the card between our read and write.
				return nil, ErrInvalidCard
			}
			return nil, err
		}
		c.PINHash = h
		c.LastUsedAt = &now
		return c, nil
	}

	if pin == "" {
		return nil, ErrPINRequired
	}
	want := hashPIN(s.pepper, c.CardID, pin)
	if subtle.ConstantTimeCompare(want, c.PINHash) != 1 {
		updated, err := s.store.RecordFailure(ctx, c.ClientID, c.Subject, c.CardID, s.maxAttempts, now)
		if errors.Is(err, ErrConflict) {
			// Locked or replaced by a concurrent request.
			return nil, ErrLocked
		}
		if err != nil {
			return nil, err
		}
		if updated.Locked() {
			return nil, ErrLocked
		}
		return nil, &WrongPINError{Remaining: s.maxAttempts - updated.FailedAttempts}
	}
	if err := s.store.RecordSuccess(ctx, c.ClientID, c.Subject, c.CardID, s.maxAttempts, now); err != nil {
		if errors.Is(err, ErrConflict) {
			// Replaced, or locked by concurrent wrong PINs: either way this
			// login must not go through.
			return nil, ErrLocked
		}
		return nil, err
	}
	c.FailedAttempts = 0
	c.LastUsedAt = &now
	return c, nil
}

// lookup resolves a token to its current card, or ErrInvalidCard.
func (s *Service) lookup(ctx context.Context, token string) (*Card, error) {
	cardID, ok := parseToken(token)
	if !ok {
		return nil, ErrInvalidCard
	}
	clientID, subject, found, err := s.store.Lookup(ctx, cardID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrInvalidCard
	}
	c, err := s.store.Get(ctx, clientID, subject)
	if err != nil {
		return nil, err
	}
	if c == nil || c.CardID != cardID || subtle.ConstantTimeCompare(c.SecretHash, hashToken(token)) != 1 {
		return nil, ErrInvalidCard
	}
	return c, nil
}

func validSubject(subject string) error {
	if subject == "" || len(subject) > maxSubjectLength {
		return ErrInvalidSubject
	}
	return nil
}
