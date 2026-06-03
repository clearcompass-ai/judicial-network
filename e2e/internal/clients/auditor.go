package clients

import (
	"strconv"

	"github.com/clearcompass-ai/judicial-network/e2e/internal/httpx"
)

// Auditor is a typed client for the auditor service (L9).
type Auditor struct{ *httpx.Client }

// NewAuditor returns an auditor client rooted at base.
func NewAuditor(base string) *Auditor { return &Auditor{httpx.New(base)} }

// Version is GET /version (S3.1).
func (a *Auditor) Version() (map[string]any, int, error) {
	m := map[string]any{}
	code, err := a.GetJSON("/version", &m)
	return m, code, err
}

// GossipSince is GET /v1/gossip/since (S6.3, T2); raw until the feed shape is
// pinned (see types.SignedEvent note).
func (a *Auditor) GossipSince(cursor string, limit int) (int, []byte, error) {
	return a.GetRaw("/v1/gossip/since?cursor=" + cursor + "&limit=" + strconv.Itoa(limit))
}
