/*
FILE PATH: api/handlers/verify_origin.go

DESCRIPTION:
    GET /v1/verify/origin/{logID}/{pos}

    Reads the entry at {pos} from {logID}'s operator, runs
    EvaluateOrigin (guide §23.1), returns the entity's current
    protocol state.

    EvaluateOrigin is O(1): it reads the entry's SMT leaf
    (Origin_Tip, Authority_Tip) and reports whether the entity
    is live, revoked, pending, or advanced.

    This is the fundamental "what is this entry's state?" query.
    Business APIs call this to determine case status, delegation
    liveness, enforcement activity — but the interpretation of
    what that state MEANS is theirs, not ours.

KEY DEPENDENCIES:
    - ortholog-sdk/verifier: EvaluateOrigin (guide §23.1)
    - ortholog-sdk/log: OperatorQueryAPI (guide §27.3)
*/
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// Dependencies shared across all handlers.
type Dependencies struct {
	// LogQueries maps log DID → operator query API.
	LogQueries map[string]sdklog.OperatorQueryAPI

	OriginEvaluator    verifier.OriginEvaluator
	AuthorityEvaluator verifier.AuthorityEvaluator
	ConditionEvaluator verifier.ConditionEvaluator
	ContestEvaluator   verifier.ContestEvaluator
	DelegationWalker   verifier.DelegationWalker
	CrossLogVerifier   verifier.CrossLogVerifier
	FraudProofVerifier verifier.FraudProofVerifier
}

// resolveLog finds the operator query API for a given log identifier.
func (d *Dependencies) resolveLog(logID string) (sdklog.OperatorQueryAPI, bool) {
	q, ok := d.LogQueries[logID]
	return q, ok
}

// VerifyOriginHandler handles GET /v1/verify/origin/{logID}/{pos}.
type VerifyOriginHandler struct {
	deps *Dependencies
}

func NewVerifyOriginHandler(deps *Dependencies) *VerifyOriginHandler {
	return &VerifyOriginHandler{deps: deps}
}

func (h *VerifyOriginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logID := r.PathValue("logID")
	posStr := r.PathValue("pos")

	query, ok := h.deps.resolveLog(logID)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown log")
		return
	}

	pos, err := strconv.ParseUint(posStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid position")
		return
	}

	entry, err := query.FetchEntry(pos)
	if err != nil {
		writeError(w, http.StatusNotFound, "entry not found")
		return
	}

	result, err := h.deps.OriginEvaluator.EvaluateOrigin(pos, entry.Entry)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "origin evaluation failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"log_id":        logID,
		"position":      pos,
		"origin_tip":    result.OriginTip,
		"authority_tip": result.AuthorityTip,
		"state":         result.State,
		"signer_did":    entry.Entry.SignerDID(),
	})
}

// ─── Shared response helpers ────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
