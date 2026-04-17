package handlers

import (
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// VerifyDelegationHandler handles GET /v1/verify/delegation/{logID}/{pos}.
type VerifyDelegationHandler struct{ deps *Dependencies }

func NewVerifyDelegationHandler(deps *Dependencies) *VerifyDelegationHandler {
	return &VerifyDelegationHandler{deps: deps}
}

type delegationHop struct {
	DelegateDID string            `json:"delegate_did"`
	SignerDID   string            `json:"signer_did"`
	Depth       int               `json:"depth"`
	IsLive      bool              `json:"is_live"`
	Position    types.LogPosition `json:"position"`
	RawPayload  []byte            `json:"raw_payload,omitempty"`
}

func (h *VerifyDelegationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logID := r.PathValue("logID")
	posStr := r.PathValue("pos")

	pos, err := strconv.ParseUint(posStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid position")
		return
	}

	fetcher, err := h.deps.fetcherFor(logID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	query, _ := h.deps.resolveLog(logID)

	tree, err := verifier.WalkDelegationTree(verifier.WalkDelegationTreeParams{
		RootEntityPos: types.LogPosition{LogDID: logID, Sequence: pos},
		Fetcher:       fetcher,
		LeafReader:    h.deps.LeafReader,
		Querier:       query,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delegation walk failed")
		return
	}

	flat := verifier.FlattenTree(tree)
	hops := make([]delegationHop, 0, len(flat))
	for _, node := range flat {
		hops = append(hops, delegationHop{
			DelegateDID: node.DelegateDID,
			SignerDID:   node.SignerDID,
			Depth:       node.Depth,
			IsLive:      node.IsLive,
			Position:    node.Position,
			RawPayload:  node.RawPayload,
		})
	}

	live := verifier.LiveDelegations(tree)
	liveDIDs := make([]string, 0, len(live))
	for _, node := range live {
		liveDIDs = append(liveDIDs, node.DelegateDID)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"root_position":   pos,
		"total_delegates": len(hops),
		"live_delegates":  liveDIDs,
		"delegation_tree": hops,
	})
}
