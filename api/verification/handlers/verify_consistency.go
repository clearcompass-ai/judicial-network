// FILE PATH: api/verification/handlers/verify_consistency.go
//
// DESCRIPTION:
//
//	Phase 8 — Static-CT consistency verification endpoint.
//	Surfaces verifier.VerifyConsistency at /v1/verify/consistency
//	so independent auditors (defense counsel, transparency
//	organisations, peer ledgers) can prove a court's log is
//	append-only between two cosigned tree heads WITHOUT
//	trusting the court's API.
//
//	Trust Alignment 6 (Zero-Trust Dual Verification): "An
//	auditor does not ask the Ledger for the answer. The auditor
//	pulls the Static CT .p tiles and the raw entry payloads,
//	utilising the SDK's local verifier to recompute the Merkle
//	math entirely on its own CPU."
//
//	This handler fetches tiles via a per-request
//	tessera_client.TileFetcherFunc closure pointed at the
//	source log's HTTP tile API. The closure shares the
//	request's deadline so a slow tile fetch surfaces to the
//	caller as a request timeout rather than a server-side hang.
//
// REQUEST SHAPE:
//
//	POST /v1/verify/consistency
//	{
//	  "source_log_did": "did:web:courts.davidson.example",
//	  "old_head": {"tree_size": 1000, "root_hash": "<hex>"},
//	  "new_head": {"tree_size": 2000, "root_hash": "<hex>"},
//	  "tile_base_url": "https://ledger.davidson.example"
//	}
//
// RESPONSE:
//
//	{"consistent": true}   on success
//	{"consistent": false, "error": "..."}   on rejection
//
// KEY DEPENDENCIES:
//   - attesta/verifier: VerifyConsistency
//   - attesta/log: NewTesseraFetcher (HTTP-backed tile reader)
//   - attesta/types: TreeHead
package handlers

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// VerifyConsistencyHandler exposes verifier.VerifyConsistency
// over HTTP. Unauthenticated by design (the verification is
// cryptographic; trust derives from the cosigned tree heads the
// caller supplies, not from the API surface).
type VerifyConsistencyHandler struct{ deps *Dependencies }

// NewVerifyConsistencyHandler constructs the handler.
func NewVerifyConsistencyHandler(deps *Dependencies) *VerifyConsistencyHandler {
	return &VerifyConsistencyHandler{deps: deps}
}

// consistencyRequest carries the two heads the caller wants to
// prove consistent plus the source log's tile-API base URL.
//
// The caller supplies tile_base_url explicitly rather than the
// handler resolving it: cross-jurisdiction consistency checks
// frequently target a peer court the JN instance does not have a
// configured TreeHeadClient against, and we want this endpoint
// to remain useful for those one-off audits without operational
// pre-wiring.
type consistencyRequest struct {
	SourceLogDID string         `json:"source_log_did"`
	OldHead      consistencyTH  `json:"old_head"`
	NewHead      consistencyTH  `json:"new_head"`
	TileBaseURL  string         `json:"tile_base_url"`
}

// consistencyTH is the wire shape of one cosigned-head pair.
// Caller supplies tree_size + root_hash as hex; the handler
// converts to types.TreeHead for the SDK call.
type consistencyTH struct {
	TreeSize uint64 `json:"tree_size"`
	RootHash string `json:"root_hash"`
}

func (h *VerifyConsistencyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req consistencyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TileBaseURL == "" {
		writeError(w, http.StatusBadRequest, "tile_base_url required")
		return
	}
	oldHead, err := req.OldHead.toTreeHead()
	if err != nil {
		writeError(w, http.StatusBadRequest, "old_head: "+err.Error())
		return
	}
	newHead, err := req.NewHead.toTreeHead()
	if err != nil {
		writeError(w, http.StatusBadRequest, "new_head: "+err.Error())
		return
	}
	fetcher, err := sdklog.NewTesseraFetcher(sdklog.TesseraFetcherConfig{
		BaseURL: req.TileBaseURL,
		Timeout: 15 * time.Second,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "tile_base_url: "+err.Error())
		return
	}

	// Cryptographic check — the only thing that matters. If the
	// SDK accepts the proof, the log is provably consistent
	// regardless of any other API claim.
	verifyErr := verifier.VerifyConsistency(ctx, oldHead, newHead, fetcher)
	if verifyErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"consistent":     false,
			"source_log_did": req.SourceLogDID,
			"error":          verifyErr.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"consistent":     true,
		"source_log_did": req.SourceLogDID,
		"old_tree_size":  oldHead.TreeSize,
		"new_tree_size":  newHead.TreeSize,
	})
}

// toTreeHead decodes the hex-encoded root hash and returns the
// SDK shape. Returns an error if the hex is malformed or the
// length is not exactly 32 bytes.
func (c consistencyTH) toTreeHead() (types.TreeHead, error) {
	if c.RootHash == "" {
		return types.TreeHead{}, errors.New("root_hash required")
	}
	raw, err := hex.DecodeString(c.RootHash)
	if err != nil {
		return types.TreeHead{}, errors.New("root_hash: invalid hex")
	}
	if len(raw) != 32 {
		return types.TreeHead{}, errors.New("root_hash: must be 32 bytes")
	}
	var rh [32]byte
	copy(rh[:], raw)
	return types.TreeHead{TreeSize: c.TreeSize, RootHash: rh}, nil
}
