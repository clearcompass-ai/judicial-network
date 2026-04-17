/*
FILE PATH: api/handlers/verify_delegation.go

DESCRIPTION:
    GET /v1/verify/delegation/{logID}/{did}

    Walks the delegation tree rooted at {did} on {logID}. Returns
    every delegation from that DID: direct delegates, their
    sub-delegates (depth 2), and their sub-sub-delegates (depth 3,
    max). Each hop includes liveness status.

    Uses WalkDelegationTree (guide §24.6) which returns the full
    tree structure with FlattenTree and LiveDelegations helpers.

    Business APIs use this to build officer rosters, check if a
    specific delegate is currently authorized, or visualize the
    delegation hierarchy. This endpoint returns raw delegation data;
    the business layer interprets scope_limit from Domain Payloads.

KEY DEPENDENCIES:
    - ortholog-sdk/verifier: WalkDelegationTree, FlattenTree,
      LiveDelegations (guide §24.6)
*/
package handlers

import (
	"net/http"
)

// VerifyDelegationHandler handles GET /v1/verify/delegation/{logID}/{did}.
type VerifyDelegationHandler struct {
	deps *Dependencies
}

func NewVerifyDelegationHandler(deps *Dependencies) *VerifyDelegationHandler {
	return &VerifyDelegationHandler{deps: deps}
}

func (h *VerifyDelegationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logID := r.PathValue("logID")
	did := r.PathValue("did")

	if did == "" {
		writeError(w, http.StatusBadRequest, "missing DID")
		return
	}

	_, ok := h.deps.resolveLog(logID)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown log")
		return
	}

	// Walk the full delegation tree from this DID.
	tree, err := h.deps.DelegationWalker.WalkDelegationTree(logID, did)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delegation tree walk failed")
		return
	}

	// Flatten for the response — each node with its depth, delegate
	// DID, delegator DID, liveness, and raw Domain Payload (the
	// business layer reads scope_limit from this).
	type delegationHop struct {
		DelegateDID  string `json:"delegate_did"`
		DelegatorDID string `json:"delegator_did"`
		Depth        int    `json:"depth"`
		Live         bool   `json:"live"`
		LogPosition  uint64 `json:"log_position"`
		DomainPayload any   `json:"domain_payload"`
	}

	flat := tree.FlattenTree()
	hops := make([]delegationHop, 0, len(flat))
	for _, node := range flat {
		hops = append(hops, delegationHop{
			DelegateDID:  node.DelegateDID,
			DelegatorDID: node.DelegatorDID,
			Depth:        node.Depth,
			Live:         node.Live,
			LogPosition:  node.LogPosition,
			DomainPayload: node.DomainPayload,
		})
	}

	// Also compute the live-only subset.
	live := tree.LiveDelegations()
	liveDIDs := make([]string, 0, len(live))
	for _, node := range live {
		liveDIDs = append(liveDIDs, node.DelegateDID)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"log_id":       logID,
		"root_did":     did,
		"delegations":  hops,
		"total":        len(hops),
		"live_count":   len(liveDIDs),
		"live_delegates": liveDIDs,
	})
}
