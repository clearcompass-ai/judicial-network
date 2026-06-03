package clients

import "github.com/clearcompass-ai/judicial-network/e2e/internal/httpx"

// Witness is a typed client for a witness daemon (L8).
type Witness struct{ *httpx.Client }

// NewWitness returns a witness client rooted at base.
func NewWitness(base string) *Witness { return &Witness{httpx.New(base)} }

// Cosign is POST /v1/cosign (S2.1, S2.2, S2.4). Body is the raw
// cosign.WireRequest JSON; scenarios pass crafted/garbage bodies for the
// negative checks. A full valid request needs the SDK's WireRequest builder
// (tracked with the cosign-verify prerequisite H5).
func (w *Witness) Cosign(body []byte) (int, []byte, error) {
	return w.PostRaw("/v1/cosign", "application/json", body)
}

// Metrics is GET /metrics (S2.5).
func (w *Witness) Metrics() (int, error) {
	code, _, err := w.GetRaw("/metrics")
	return code, err
}
