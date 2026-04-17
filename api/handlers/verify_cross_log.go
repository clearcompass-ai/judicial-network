/*
FILE PATH: api/handlers/verify_cross_log.go

DESCRIPTION:
    POST /v1/verify/cross-log

    Verifies a compound proof that an entry on one log is consistent
    with another log's view, through the anchor hierarchy.

    Use case: Davidson County verifying a Shelby County case entry.
    The proof traverses: Shelby log → state anchor → Davidson log.
    Each hop is ~2.1 KB. Three hops: ~6.3 KB.

    The caller provides the proof (obtained from the source log's
    operator or constructed via SDK BuildCrossLogProof). This endpoint
    verifies it against the anchor hierarchy the verification service
    is configured to trust.

    Domain-agnostic: a hospital verifying a pharmacy credential
    across networks uses the same endpoint with the same proof format.

KEY DEPENDENCIES:
    - ortholog-sdk/verifier: VerifyCrossLogProof (guide §24.1)
*/
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// VerifyCrossLogHandler handles POST /v1/verify/cross-log.
type VerifyCrossLogHandler struct {
	deps *Dependencies
}

func NewVerifyCrossLogHandler(deps *Dependencies) *VerifyCrossLogHandler {
	return &VerifyCrossLogHandler{deps: deps}
}

// CrossLogRequest is the request body.
type CrossLogRequest struct {
	// Proof is the compound proof to verify, as returned by
	// BuildCrossLogProof or obtained from a peer.
	Proof *verifier.CrossLogProofResult `json:"proof"`
}

func (h *VerifyCrossLogHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req CrossLogRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Proof == nil {
		writeError(w, http.StatusBadRequest, "proof is required")
		return
	}

	// Verify the compound proof against the anchor hierarchy.
	err := h.deps.CrossLogVerifier.VerifyCrossLogProof(req.Proof)

	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":  false,
			"error":  err.Error(),
			"source": req.Proof.SourceLogDID,
			"target": req.Proof.TargetLogDID,
			"hops":   req.Proof.HopCount,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid":          true,
		"source_log":     req.Proof.SourceLogDID,
		"source_pos":     req.Proof.SourceEntryPos,
		"target_log":     req.Proof.TargetLogDID,
		"anchor_log":     req.Proof.AnchorLogDID,
		"hops":           req.Proof.HopCount,
		"proof_size_bytes": req.Proof.ProofSizeBytes,
	})
}
