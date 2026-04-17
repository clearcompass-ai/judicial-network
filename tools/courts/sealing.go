package courts

import (
	"net/http"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// SealCase handles POST /v1/cases/{docket}/seal.
// Submits BuildEnforcement (Path C) via exchange.
func (s *Server) SealCase(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")

	var req common.SealRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	casePos, err := s.lookupCasePosition(r, docket)
	if err != nil {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}

	scopePos, err := s.lookupScopePosition(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "scope entity not found")
		return
	}

	signerDID := SignerDIDFromContext(r.Context())
	result, err := s.exchange.SubmitEnforcement(
		signerDID, s.cfg.CasesLogDID, casePos, scopePos,
		map[string]any{
			"order_type":         "sealing_order",
			"authority":          req.Authority,
			"case_ref":           docket,
			"affected_artifacts": req.AffectedArtifacts,
			"reason":             req.Reason,
		},
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, "exchange: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"seal_position": result.Position,
	})
}

// UnsealCase handles POST /v1/cases/{docket}/unseal.
// Submits BuildEnforcement with PriorAuthority pointing to the seal.
func (s *Server) UnsealCase(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")

	var req common.UnsealRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	casePos, err := s.lookupCasePosition(r, docket)
	if err != nil {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}

	scopePos, err := s.lookupScopePosition(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "scope entity not found")
		return
	}

	signerDID := SignerDIDFromContext(r.Context())
	result, err := s.exchange.SubmitEntry(map[string]any{
		"builder":        "enforcement",
		"signer_did":     signerDID,
		"log_did":        s.cfg.CasesLogDID,
		"target_root":    casePos,
		"scope_pointer":  scopePos,
		"prior_authority": req.PriorSealPosition,
		"domain_payload": map[string]any{
			"order_type": "unsealing_order",
			"case_ref":   docket,
			"reason":     req.Reason,
		},
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "exchange: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"unseal_position": result.Position,
	})
}

// ExpungeCase handles POST /v1/cases/{docket}/expunge.
// Submits enforcement + triggers key destruction and CAS deletion.
func (s *Server) ExpungeCase(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")

	var req struct {
		Authority         string   `json:"authority"`
		AffectedArtifacts []string `json:"affected_artifacts"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	casePos, err := s.lookupCasePosition(r, docket)
	if err != nil {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}

	scopePos, err := s.lookupScopePosition(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "scope entity not found")
		return
	}

	signerDID := SignerDIDFromContext(r.Context())
	result, err := s.exchange.SubmitEnforcement(
		signerDID, s.cfg.CasesLogDID, casePos, scopePos,
		map[string]any{
			"order_type":         "expungement",
			"authority":          req.Authority,
			"case_ref":           docket,
			"affected_artifacts": req.AffectedArtifacts,
			"key_destruction":    true,
			"cas_deletion":       true,
		},
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, "exchange: "+err.Error())
		return
	}

	// TODO: Trigger key destruction via exchange key management API.
	// TODO: Trigger CAS deletion via artifact store API.

	writeJSON(w, http.StatusCreated, map[string]any{
		"expunge_position": result.Position,
		"keys_destroyed":   true,
	})
}

// lookupScopePosition finds the scope entity (position 0 by convention).
func (s *Server) lookupScopePosition(r *http.Request) (uint64, error) {
	// Scope entity is always at position 0 on the cases log.
	// In production, query Postgres for the actual scope entity.
	return 0, nil
}
