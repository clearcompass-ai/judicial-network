package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// VerifyFraudProofHandler handles POST /v1/verify/fraud-proof.
type VerifyFraudProofHandler struct{ deps *Dependencies }

func NewVerifyFraudProofHandler(deps *Dependencies) *VerifyFraudProofHandler {
	return &VerifyFraudProofHandler{deps: deps}
}

func (h *VerifyFraudProofHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Commitment types.SMTDerivationCommitment `json:"commitment"`
		LogDID     string                        `json:"log_did"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	fetcher, err := h.deps.fetcherFor(req.LogDID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	// Empty prior state replays the commitment from genesis. A future
	// optimization can persist warm prior state per log to speed up
	// large-batch verification.
	priorState := smt.NewInMemoryLeafStore()
	result, err := verifier.VerifyDerivationCommitment(
		req.Commitment, priorState, fetcher, h.deps.SchemaResolver, req.LogDID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "fraud proof verification failed")
		return
	}

	writeJSON(w, http.StatusOK, result)
}
