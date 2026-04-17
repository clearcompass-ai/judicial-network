/*
FILE PATH: api/handlers/verify_authority.go

DESCRIPTION:
    GET /v1/verify/authority/{logID}/{pos}

    Full verification report for an entry. Runs three SDK evaluators:

    1. EvaluateAuthority (guide §23.2)
       Is the delegation chain valid? Each hop live? Does the chain
       connect signer → target root's authority?

    2. CheckActivationReady (guide §23.3)
       Are activation conditions met? Cosignature threshold reached?
       Activation delay expired?

    3. EvaluateContest (guide §23.4)
       Has this entry been contested or overridden? Is there a
       pending contest entry on the Authority_Tip?

    The response is the complete protocol-level verification state.
    A business API reads this and applies domain policy (e.g., "this
    sealing order's cosignatures aren't met → show as pending").

KEY DEPENDENCIES:
    - ortholog-sdk/verifier: EvaluateAuthority, CheckActivationReady,
      EvaluateContest (guide §§23.2, 23.3, 23.4)
*/
package handlers

import (
	"net/http"
	"strconv"
	"time"
)

// VerifyAuthorityHandler handles GET /v1/verify/authority/{logID}/{pos}.
type VerifyAuthorityHandler struct {
	deps *Dependencies
}

func NewVerifyAuthorityHandler(deps *Dependencies) *VerifyAuthorityHandler {
	return &VerifyAuthorityHandler{deps: deps}
}

func (h *VerifyAuthorityHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	// 1. Authority chain evaluation.
	authorityResult, err := h.deps.AuthorityEvaluator.EvaluateAuthority(pos, entry.Entry)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authority evaluation failed")
		return
	}

	// 2. Activation condition check.
	var activationData map[string]any
	conditionResult, err := h.deps.ConditionEvaluator.CheckActivationReady(pos, entry.Entry, time.Now())
	if err != nil {
		// Non-fatal: some entries don't have activation conditions
		// (commentary, root entities). Report the error but continue.
		activationData = map[string]any{
			"applicable": false,
			"note":       err.Error(),
		}
	} else {
		activationData = map[string]any{
			"applicable":           true,
			"ready":                conditionResult.Ready,
			"cosignatures_met":     conditionResult.CosignaturesMet,
			"cosignatures_required": conditionResult.CosignaturesRequired,
			"cosignatures_present": conditionResult.CosignaturesPresent,
			"delay_expired":        conditionResult.DelayExpired,
			"activation_delay":     conditionResult.ActivationDelay,
			"earliest_activation":  conditionResult.EarliestActivation,
		}
	}

	// 3. Contest/override check.
	var contestData map[string]any
	contestResult, err := h.deps.ContestEvaluator.EvaluateContest(pos, entry.Entry)
	if err != nil {
		contestData = map[string]any{
			"applicable": false,
			"note":       err.Error(),
		}
	} else {
		contestData = map[string]any{
			"applicable":       true,
			"contested":        contestResult.Contested,
			"override_type":    contestResult.OverrideType,
			"contest_entry_pos": contestResult.ContestEntryPos,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"log_id":     logID,
		"position":   pos,
		"signer_did": entry.Entry.SignerDID(),
		"authority": map[string]any{
			"valid":           authorityResult.Valid,
			"path":            authorityResult.Path,
			"delegation_hops": authorityResult.DelegationHops,
			"depth":           authorityResult.Depth,
		},
		"activation": activationData,
		"contest":    contestData,
	})
}
