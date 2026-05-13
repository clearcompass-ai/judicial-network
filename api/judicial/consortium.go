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

// ServeHTTP — v0.3.0 collapse of the cross-court verify wire shape.
//
// Old (v0.1.0): accepted source_witness_keys_b64 + source_witness_quorum +
// source_network_id and re-assembled them per request. This duplicated
// the boot-time WitnessSets[did] entry and admitted the class of bug
// where the per-request K/keys drifted from the deployment topology.
//
// New (v0.3.0): the request supplies only source_log_did. The deps'
// WitnessSets[did] is the single source of truth for K, keys, and
// NetworkID (SDK Principle 10, Two-Tier Quorum Encapsulation). If the
// source log is unknown to the deployment, the request fails fast
// with 400 — no opportunity for inconsistent overrides.
func (h *consortiumVerifyCrossCourtHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	var req struct {
		Proof        json.RawMessage `json:"proof"`
		SourceLogDID string          `json:"source_log_did"`
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
	set, ok := h.deps.WitnessSets[req.SourceLogDID]
	if !ok || set == nil {
		writeError(w, http.StatusBadRequest,
			"no witness set for source_log_did (pre-configure via WitnessSets at boot)")
		return
	}
	verifyErr := consortium.VerifyCrossCourtProof(proof, set)
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
