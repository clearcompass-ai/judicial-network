/*
FILE PATH: api/judicial/consortium.go

DESCRIPTION:

	Consortium governance handlers — multi-court federation events.
	Most require ops-tooling-driven multi-step ceremonies; the API
	exposes the wireable pieces (member-addition/removal proposals,
	cross-court proof verification) and stubs the rest with explicit
	operational reasoning.

	  POST /v1/judicial/consortium/members/propose-addition  → ProposeMemberAddition
	  POST /v1/judicial/consortium/members/propose-removal   → ProposeMemberRemoval
	  POST /v1/judicial/consortium/cross-court-proof/verify  → VerifyCrossCourtProof
	  POST /v1/judicial/consortium/cross-court-proof/build   → 501 (cross-log compose)
	  POST /v1/judicial/consortium/members/execute-addition  → 501 (lifecycle Params)
	  POST /v1/judicial/consortium/members/execute-removal   → 501 (lifecycle Params)
	  POST /v1/judicial/consortium/members/activate-removal  → 501 (lifecycle Params)
	  POST /v1/judicial/consortium/formation                 → 501 (bootstrap script)
*/
package judicial

import (
	"encoding/json"
	"net/http"

	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/consortium"
)

func registerConsortiumRoutes(mux *http.ServeMux, deps *Dependencies) {
	mux.Handle("POST /v1/judicial/consortium/members/propose-addition", &consortiumProposeAddHandler{deps: deps})
	mux.Handle("POST /v1/judicial/consortium/members/propose-removal", &consortiumProposeRemoveHandler{deps: deps})
	mux.Handle("POST /v1/judicial/consortium/cross-court-proof/verify", &consortiumVerifyCrossCourtHandler{deps: deps})
	mux.Handle("POST /v1/judicial/consortium/cross-court-proof/build", &consortiumBuildCrossCourtHandler{deps: deps})
	mux.Handle("POST /v1/judicial/consortium/members/execute-addition", &consortiumExecuteAddHandler{deps: deps})
	mux.Handle("POST /v1/judicial/consortium/members/execute-removal", &consortiumExecuteRemoveHandler{deps: deps})
	mux.Handle("POST /v1/judicial/consortium/members/activate-removal", &consortiumActivateRemovalHandler{deps: deps})
	mux.Handle("POST /v1/judicial/consortium/formation", &consortiumFormationHandler{deps: deps})
}

// ─────────────────────────────────────────────────────────────────────
// propose-addition / propose-removal
// ─────────────────────────────────────────────────────────────────────

type consortiumProposalRequest struct {
	Destination string `json:"destination"`
	TargetDID   string `json:"target_did"`
	CourtName   string `json:"court_name"`
	Reason      string `json:"reason"`
}

type consortiumProposeAddHandler struct{ deps *Dependencies }

func (h *consortiumProposeAddHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proposer := requireCaller(w, r)
	if proposer == "" {
		return
	}
	var req consortiumProposalRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TargetDID == "" || req.Destination == "" {
		writeError(w, http.StatusBadRequest, "target_did and destination required")
		return
	}
	proposal, err := consortium.ProposeMemberAddition(consortium.MembershipProposal{
		Destination: req.Destination,
		ProposerDID: proposer,
		TargetDID:   req.TargetDID,
		CourtName:   req.CourtName,
		Reason:      req.Reason,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, proposal)
}

type consortiumProposeRemoveHandler struct{ deps *Dependencies }

func (h *consortiumProposeRemoveHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proposer := requireCaller(w, r)
	if proposer == "" {
		return
	}
	var req consortiumProposalRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TargetDID == "" || req.Destination == "" {
		writeError(w, http.StatusBadRequest, "target_did and destination required")
		return
	}
	proposal, err := consortium.ProposeMemberRemoval(consortium.MembershipProposal{
		Destination: req.Destination,
		ProposerDID: proposer,
		TargetDID:   req.TargetDID,
		CourtName:   req.CourtName,
		Reason:      req.Reason,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, proposal)
}

// ─────────────────────────────────────────────────────────────────────
// cross-court-proof verify
// ─────────────────────────────────────────────────────────────────────

// Mirror of /v1/judicial/verification/cross-log-proof but routed
// under the consortium namespace for callers that treat cross-court
// verification as a federation concern. The two paths share their
// underlying implementation (verifier.VerifyCrossLogProof) and are
// wire-equivalent.
type consortiumVerifyCrossCourtHandler struct{ deps *Dependencies }

func (h *consortiumVerifyCrossCourtHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	if h.deps.BLSVerifier == nil {
		writeError(w, http.StatusInternalServerError, "BLSVerifier must be configured")
		return
	}
	var req struct {
		Proof                json.RawMessage `json:"proof"`
		SourceLogDID         string          `json:"source_log_did"`
		SourceWitnessKeysB64 []string        `json:"source_witness_keys_b64,omitempty"`
		SourceWitnessQuorum  int             `json:"source_witness_quorum,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Proof) == 0 || req.SourceLogDID == "" {
		writeError(w, http.StatusBadRequest, "proof and source_log_did required")
		return
	}
	var proof types.CrossLogProof
	if err := json.Unmarshal(req.Proof, &proof); err != nil {
		writeError(w, http.StatusBadRequest, "proof must be a valid CrossLogProof JSON")
		return
	}
	keys, err := decodeWitnessKeys(req.SourceWitnessKeysB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(keys) == 0 {
		keys = h.deps.WitnessKeys[req.SourceLogDID]
	}
	quorum := req.SourceWitnessQuorum
	if quorum == 0 {
		quorum = h.deps.WitnessQuorum[req.SourceLogDID]
	}
	networkID := h.deps.WitnessNetwork[req.SourceLogDID]
	if len(keys) == 0 || quorum == 0 || networkID.IsZero() {
		writeError(w, http.StatusBadRequest,
			"source_witness_keys + quorum + network_id required (or pre-configured for the source log)")
		return
	}
	verifyErr := consortium.VerifyCrossCourtProof(proof, keys, quorum, networkID, h.deps.BLSVerifier)
	if verifyErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{"verified": false, "error": verifyErr.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verified": true})
}

// ─────────────────────────────────────────────────────────────────────
// 501 stubs — operational-tooling territory
// ─────────────────────────────────────────────────────────────────────

type consortiumBuildCrossCourtHandler struct{ deps *Dependencies }

func (h *consortiumBuildCrossCourtHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"BuildCrossCourtProof requires source/local Merkle provers + cosigned tree heads; ops-tool composes")
}

type consortiumExecuteAddHandler struct{ deps *Dependencies }

func (h *consortiumExecuteAddHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"ExecuteMemberAddition requires lifecycle.ExecuteAmendmentParams; ops-tool composes")
}

type consortiumExecuteRemoveHandler struct{ deps *Dependencies }

func (h *consortiumExecuteRemoveHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"ExecuteMemberRemoval requires lifecycle.RemovalParams; ops-tool composes")
}

type consortiumActivateRemovalHandler struct{ deps *Dependencies }

func (h *consortiumActivateRemovalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"ActivateMemberRemoval requires lifecycle.ActivateRemovalParams; ops-tool composes")
}

type consortiumFormationHandler struct{ deps *Dependencies }

func (h *consortiumFormationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"FormConsortium is bootstrap-script-driven; submit governance log entries to /v1/entries/submit")
}
