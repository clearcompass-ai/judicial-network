package clients

import "github.com/clearcompass-ai/judicial-network/e2e/internal/httpx"

// JN is a typed client for the judicial-network enforcer (L11). It speaks
// mTLS (RequireAndVerifyClientCert), so construct it with NewJN using the
// client cert whose URI-SAN is the caller DID.
type JN struct{ *httpx.Client }

// NewJN builds an mTLS client for the enforcer at base.
func NewJN(base, caFile, certFile, keyFile string) (*JN, error) {
	c, err := httpx.NewMTLS(base, caFile, certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &JN{c}, nil
}

// PeerConsistency is GET /v1/judicial/monitoring/peer-consistency — the
// verify-only trusted-head state (T3/T7/T9). Needs prerequisite H3; until
// that endpoint exists this is a real call returning 404 (not a stub).
func (j *JN) PeerConsistency() (int, []byte, error) {
	return j.GetRaw("/v1/judicial/monitoring/peer-consistency")
}

// Judicial is the generic extension point for the /v1/judicial/* surface:
// POST body to path, decode a 2xx into out. Add typed wrappers per endpoint
// as scenarios need them (e.g. OpenCase → POST /v1/judicial/cases).
func (j *JN) Judicial(path string, body, out any) (int, error) {
	return j.PostJSON(path, body, out)
}
