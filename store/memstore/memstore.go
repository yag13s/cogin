// Package memstore is an in-memory implementation of the cogin stores, for
// tests and local experiments. Data is lost when the process exits.
package memstore

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/yag13s/cogin/card"
	"github.com/yag13s/cogin/oidc"
)

type key struct{ clientID, subject string }

type index struct{ clientID, subject string }

// Store implements card.Store and oidc.CodeStore.
type Store struct {
	mu    sync.Mutex
	cards map[key]*card.Card
	index map[string]index
	codes map[string]storedCode
}

type storedCode struct {
	code    oidc.AuthCode
	expires time.Time
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		cards: map[key]*card.Card{},
		index: map[string]index{},
		codes: map[string]storedCode{},
	}
}

func clone(c *card.Card) *card.Card {
	if c == nil {
		return nil
	}
	cp := *c
	cp.SecretHash = append([]byte(nil), c.SecretHash...)
	cp.PINHash = append([]byte(nil), c.PINHash...)
	if c.LockedAt != nil {
		t := *c.LockedAt
		cp.LockedAt = &t
	}
	if c.LastUsedAt != nil {
		t := *c.LastUsedAt
		cp.LastUsedAt = &t
	}
	if c.ActivateBy != nil {
		t := *c.ActivateBy
		cp.ActivateBy = &t
	}
	if c.ExpiresAt != nil {
		t := *c.ExpiresAt
		cp.ExpiresAt = &t
	}
	return &cp
}

// Get implements card.Store.
func (s *Store) Get(_ context.Context, clientID, subject string) (*card.Card, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.cards[key{clientID, subject}]), nil
}

// Put implements card.Store.
func (s *Store) Put(_ context.Context, c *card.Card, prevGen int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key{c.ClientID, c.Subject}
	cur := s.cards[k]
	if (cur == nil && prevGen != 0) || (cur != nil && cur.Generation != prevGen) {
		return card.ErrConflict
	}
	s.cards[k] = clone(c)
	return nil
}

// List implements card.Store.
func (s *Store) List(_ context.Context, clientID string) ([]*card.Card, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*card.Card
	for k, c := range s.cards {
		if k.clientID == clientID {
			out = append(out, clone(c))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out, nil
}

// PutIndex implements card.Store.
func (s *Store) PutIndex(_ context.Context, cardID, clientID, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.index[cardID] = index{clientID, subject}
	return nil
}

// Lookup implements card.Store.
func (s *Store) Lookup(_ context.Context, cardID string) (string, string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ix, ok := s.index[cardID]
	return ix.clientID, ix.subject, ok, nil
}

// DeleteIndex implements card.Store.
func (s *Store) DeleteIndex(_ context.Context, cardID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.index, cardID)
	return nil
}

func (s *Store) current(clientID, subject, cardID string) (*card.Card, error) {
	c := s.cards[key{clientID, subject}]
	if c == nil || c.CardID != cardID {
		return nil, card.ErrConflict
	}
	return c, nil
}

// RecordFailure implements card.Store.
func (s *Store) RecordFailure(_ context.Context, clientID, subject, cardID string, maxAttempts int, now time.Time) (*card.Card, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.current(clientID, subject, cardID)
	if err != nil {
		return nil, err
	}
	if c.LockedAt != nil || c.FailedAttempts >= maxAttempts {
		return nil, card.ErrConflict
	}
	c.FailedAttempts++
	c.UpdatedAt = now
	if c.FailedAttempts >= maxAttempts {
		t := now
		c.LockedAt = &t
	}
	return clone(c), nil
}

// RecordSuccess implements card.Store.
func (s *Store) RecordSuccess(_ context.Context, clientID, subject, cardID string, maxAttempts int, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.current(clientID, subject, cardID)
	if err != nil {
		return err
	}
	if c.LockedAt != nil || c.FailedAttempts >= maxAttempts {
		return card.ErrConflict
	}
	c.FailedAttempts = 0
	t := now
	c.LastUsedAt = &t
	return nil
}

// SetPIN implements card.Store.
func (s *Store) SetPIN(_ context.Context, clientID, subject, cardID string, pinHash []byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.current(clientID, subject, cardID)
	if err != nil {
		return err
	}
	if len(c.PINHash) > 0 {
		return card.ErrConflict
	}
	c.PINHash = append([]byte(nil), pinHash...)
	c.UpdatedAt = now
	t := now
	c.LastUsedAt = &t
	return nil
}

// Unlock implements card.Store.
func (s *Store) Unlock(_ context.Context, clientID, subject string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cards[key{clientID, subject}]
	if c == nil {
		return card.ErrNotFound
	}
	c.LockedAt = nil
	c.FailedAttempts = 0
	c.UpdatedAt = now
	return nil
}

// PutCode implements oidc.CodeStore.
func (s *Store) PutCode(_ context.Context, hash string, code *oidc.AuthCode, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[hash] = storedCode{code: *code, expires: time.Now().Add(ttl)}
	return nil
}

// ConsumeCode implements oidc.CodeStore.
func (s *Store) ConsumeCode(_ context.Context, hash string) (*oidc.AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc, ok := s.codes[hash]
	delete(s.codes, hash)
	if !ok || time.Now().After(sc.expires) {
		return nil, nil
	}
	c := sc.code
	return &c, nil
}
