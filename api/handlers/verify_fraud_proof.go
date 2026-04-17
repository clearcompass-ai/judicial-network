/*
FILE PATH: api/handlers/verify_fraud_proof.go

DESCRIPTION:
    POST /v1/verify/fraud-proof

    Verifies a fraud proof by replaying a derivation commitment
    against entries. If the operator's published commitment doesn't
    match the deterministic replay, the operator misbehaved.

    Uses VerifyDerivationCommitment (guide §24.3): takes a
    commitment (tree head + entry range) and replays ProcessBatch
    to check that the SMT root matches. Deterministic — same
    entries always produce same root.

    This is the CT equivalent of detecting a split view: if an
    operator publishes different tree heads to different witnesses,
    the commitment won't verify against the entries.

    Domain-agnostic: any log operator on any network can be audited
    with this endpoint.

KEY DEPENDENCIES:
    - ortholog-sdk/verifier: VerifyDerivationCommitment (guide §24.3)
*/
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// VerifyFraudProofHandler handles POST /v1/verify/fraud-proof.
type VerifyFraudProofHandler struct {
	deps *Dependencies
}

func NewVerifyFraudProofHandler(deps *Dependencies) *VerifyFraudProofHandler {
	return &VerifyFraudProofHandler{deps: deps}
}

// FraudProofRequest is the request body.
type FraudProofRequest struct {
	// LogID identifies which log's operator is being audited.
	LogID string `json:"log_id"`

	// Commitment is the operator's published derivation commitment
	// (tree head at a specific size + the entries in that range).
	Commitment *verifier.DerivationCommitment `json:"commitment"`
}

func (h *VerifyFraudProofHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req FraudProofRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Commitment == nil {
		writeError(w, http.StatusBadRequest, "commitment is required")
		return
	}

	if req.LogID == "" {
		writeError(w, http.StatusBadRequest, "log_id is required")
		return
	}

	_, ok := h.deps.resolveLog(req.LogID)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown log")
		return
	}

	// Replay the commitment deterministically.
	// VerifyDerivationCommitment re-runs ProcessBatch over the
	// claimed entry range and checks that the resulting SMT root
	// matches the operator's published root. If they differ, the
	// operator computed a different state transition than the entries
	// warrant — proof of misbehavior.
	result, err := h.deps.FraudProofVerifier.VerifyDerivationCommitment(
		req.LogID, req.Commitment,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "verification failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"log_id":           req.LogID,
		"valid":            result.Valid,
		"expected_root":    result.ExpectedRoot,
		"committed_root":   result.CommittedRoot,
		"entry_range_start": result.EntryRangeStart,
		"entry_range_end":  result.EntryRangeEnd,
		"entries_replayed": result.EntriesReplayed,
		"misbehavior":      !result.Valid,
	})
}
