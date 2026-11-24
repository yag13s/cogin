package server

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/yag13s/cogin/card"
	"github.com/yag13s/cogin/oidc"
)

// CardView is the management API's view of a card. It never includes
// secrets; the token itself is only returned once, by issue.
type CardView struct {
	Subject        string     `json:"subject"`
	DisplayName    string     `json:"displayName,omitempty"`
	Generation     int64      `json:"generation"`
	Active         bool       `json:"active"`
	HasPIN         bool       `json:"hasPin"`
	Locked         bool       `json:"locked"`
	FailedAttempts int        `json:"failedAttempts"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
	LastUsedAt     *time.Time `json:"lastUsedAt,omitempty"`
	// ActivateBy is the first-use deadline of a card sent as a link.
	ActivateBy *time.Time `json:"activateBy,omitempty"`
	// ExpiresAt is the end of the card's validity, if it has one.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

func viewOf(c *card.Card) CardView {
	return CardView{
		Subject:        c.Subject,
		DisplayName:    c.DisplayName,
		Generation:     c.Generation,
		Active:         c.Active(),
		HasPIN:         c.HasPIN(),
		Locked:         c.Locked(),
		FailedAttempts: c.FailedAttempts,
		CreatedAt:      c.CreatedAt,
		UpdatedAt:      c.UpdatedAt,
		LastUsedAt:     c.LastUsedAt,
		ActivateBy:     c.ActivateBy,
		ExpiresAt:      c.ExpiresAt,
	}
}

// adminClient authenticates the management API by the client's admin key.
// The key both authenticates and scopes: a client only ever sees its own
// cards.
func (s *Server) adminClient(w http.ResponseWriter, r *http.Request) (*oidc.Client, bool) {
	key, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if ok {
		// Admin keys are "{clientID}.{secret}" so the client can be found
		// without trying every registered hash.
		if id, _, found := strings.Cut(key, "."); found {
			if c := s.Clients[id]; c != nil && c.CheckAdminKey(key) {
				return c, true
			}
		}
	}
	writeError(w, http.StatusUnauthorized, "unauthorized", "invalid admin key")
	return nil, false
}

// adminListCards handles GET /admin/v1/cards[?subject=…].
func (s *Server) adminListCards(w http.ResponseWriter, r *http.Request) {
	client, ok := s.adminClient(w, r)
	if !ok {
		return
	}
	if subject := r.URL.Query().Get("subject"); subject != "" {
		c, err := s.Cards.Get(r.Context(), client.ID, subject)
		if err != nil {
			writeAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, viewOf(c))
		return
	}
	cards, err := s.Cards.List(r.Context(), client.ID)
	if err != nil {
		writeAdminError(w, err)
		return
	}
	views := make([]CardView, 0, len(cards))
	for _, c := range cards {
		views = append(views, viewOf(c))
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Subject < views[j].Subject })
	writeJSON(w, http.StatusOK, map[string]any{"cards": views})
}

type subjectRequest struct {
	Subject     string `json:"subject"`
	DisplayName string `json:"displayName"`
	// ActivateWithinSeconds (issue only) limits how long the new card can
	// wait for its first use. Use it for cards sent as a link.
	ActivateWithinSeconds int64 `json:"activateWithinSeconds"`
	// ExpiresInSeconds (issue only) ends the card's validity that long after
	// issuing. Omitted or 0 means the card does not expire.
	ExpiresInSeconds int64 `json:"expiresInSeconds"`
}

// maxExpiresIn caps a card's validity period when one is given.
const maxExpiresIn = 365 * 24 * time.Hour

// maxActivateWithin caps the first-use window: a link is meant to be opened
// soon, and a long window defeats the point of having one.
const maxActivateWithin = 30 * 24 * time.Hour

type issueResponse struct {
	// Token is the raw card secret. It is returned only here; cogin keeps
	// just its hash, so a lost printout means issuing a new card.
	Token   string   `json:"token"`
	CardURL string   `json:"cardUrl"`
	QRPNG   string   `json:"qrPng"` // base64 PNG of CardURL
	Card    CardView `json:"card"`
}

// adminIssue handles POST /admin/v1/cards/issue: issue a card, or re-issue it
// (which invalidates the previous one at the same time).
func (s *Server) adminIssue(w http.ResponseWriter, r *http.Request) {
	client, ok := s.adminClient(w, r)
	if !ok {
		return
	}
	body, ok := decodeJSON[subjectRequest](w, r)
	if !ok {
		return
	}
	within := time.Duration(body.ActivateWithinSeconds) * time.Second
	if body.ActivateWithinSeconds < 0 || within > maxActivateWithin {
		writeError(w, http.StatusBadRequest, "invalid_request", "activateWithinSeconds must be between 0 and 30 days")
		return
	}
	expiresIn := time.Duration(body.ExpiresInSeconds) * time.Second
	if body.ExpiresInSeconds < 0 || expiresIn > maxExpiresIn {
		writeError(w, http.StatusBadRequest, "invalid_request", "expiresInSeconds must be between 0 and 365 days")
		return
	}
	token, c, err := s.Cards.Issue(r.Context(), client.ID, body.Subject, body.DisplayName,
		card.IssueOptions{ActivateWithin: within, ExpiresIn: expiresIn})
	if err != nil {
		writeAdminError(w, err)
		return
	}
	cardURL := s.CardURL(token)
	png, err := qrcode.Encode(cardURL, qrcode.Medium, 512)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to render QR code")
		return
	}
	writeJSON(w, http.StatusOK, issueResponse{
		Token:   token,
		CardURL: cardURL,
		QRPNG:   base64.StdEncoding.EncodeToString(png),
		Card:    viewOf(c),
	})
}

// CardURL is the URL encoded in a card's QR code. The token goes in the
// fragment so it is not sent to the server when the URL is opened.
func (s *Server) CardURL(token string) string {
	return s.Issuer + "/c#" + token
}

// adminRevoke handles POST /admin/v1/cards/revoke.
func (s *Server) adminRevoke(w http.ResponseWriter, r *http.Request) {
	client, ok := s.adminClient(w, r)
	if !ok {
		return
	}
	body, ok := decodeJSON[subjectRequest](w, r)
	if !ok {
		return
	}
	c, err := s.Cards.Revoke(r.Context(), client.ID, body.Subject)
	if err != nil {
		writeAdminError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, viewOf(c))
}

// adminUnlock handles POST /admin/v1/cards/unlock.
func (s *Server) adminUnlock(w http.ResponseWriter, r *http.Request) {
	client, ok := s.adminClient(w, r)
	if !ok {
		return
	}
	body, ok := decodeJSON[subjectRequest](w, r)
	if !ok {
		return
	}
	c, err := s.Cards.Unlock(r.Context(), client.ID, body.Subject)
	if err != nil {
		writeAdminError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, viewOf(c))
}

func writeAdminError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, card.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no card for this subject")
	case errors.Is(err, card.ErrInvalidSubject):
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, card.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", "the card was changed concurrently; retry")
	default:
		log.Printf("admin: %v", err)
		writeError(w, http.StatusInternalServerError, "server_error", "internal error")
	}
}
