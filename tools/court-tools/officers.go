package courts

import (
	"net/http"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// CreateOfficer handles POST /v1/officers.
// Submits BuildDelegation on officers log via exchange.
func (s *Server) CreateOfficer(w http.ResponseWriter, r *http.Request) {
	var req common.OfficerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.DelegateDID == "" || req.Role == "" {
		writeError(w, http.StatusBadRequest, "delegate_did and role required")
		return
	}

	signerDID := SignerDIDFromContext(r.Context())
	result, err := s.exchange.SubmitDelegation(
		signerDID, req.DelegateDID, s.cfg.OfficersLogDID,
		map[string]any{
			"role":        req.Role,
			"division":    req.Division,
			"scope_limit": req.ScopeLimit,
		},
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, "exchange: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"delegation_position": result.Position,
	})
}

// RevokeOfficer handles DELETE /v1/officers/{did}.
func (s *Server) RevokeOfficer(w http.ResponseWriter, r *http.Request) {
	officerDID := r.PathValue("did")

	var req struct {
		Reason             string `json:"reason"`
		DelegationPosition uint64 `json:"delegation_position"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// If delegation_position not provided, look it up.
	delegPos := req.DelegationPosition
	if delegPos == 0 && s.db != nil {
		s.db.QueryRowContext(r.Context(),
			`SELECT log_position FROM officers WHERE delegate_did = $1 AND is_live = TRUE LIMIT 1`,
			officerDID,
		).Scan(&delegPos)
	}
	if delegPos == 0 {
		writeError(w, http.StatusBadRequest, "delegation_position required (or officer not found)")
		return
	}

	signerDID := SignerDIDFromContext(r.Context())
	result, err := s.exchange.SubmitRevocation(
		signerDID, s.cfg.OfficersLogDID, delegPos,
		map[string]any{
			"reason":     req.Reason,
			"officer_did": officerDID,
		},
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, "exchange: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"revocation_position": result.Position,
	})
}

// ListOfficers handles GET /v1/officers.
// Returns all live officers from Postgres.
func (s *Server) ListOfficers(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		// Fallback: call verification API for delegation tree.
		result, err := s.verify.VerifyDelegation(s.cfg.OfficersLogDID, 0)
		if err != nil {
			writeError(w, http.StatusBadGateway, "verify: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}

	rows, err := s.db.QueryContext(r.Context(), `
		SELECT delegate_did, signer_did, COALESCE(role,''), COALESCE(division,''),
		       scope_limit, log_position, is_live, depth
		FROM officers ORDER BY log_position ASC
	`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()

	var officers []common.OfficerRecord
	for rows.Next() {
		var o common.OfficerRecord
		rows.Scan(&o.DelegateDID, &o.SignerDID, &o.Role, &o.Division,
			&o.ScopeLimit, &o.LogPosition, &o.IsLive, &o.Depth)
		officers = append(officers, o)
	}

	writeJSON(w, http.StatusOK, officers)
}

// GetOfficer handles GET /v1/officers/{did}.
func (s *Server) GetOfficer(w http.ResponseWriter, r *http.Request) {
	officerDID := r.PathValue("did")

	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	var o common.OfficerRecord
	err := s.db.QueryRowContext(r.Context(), `
		SELECT delegate_did, signer_did, COALESCE(role,''), COALESCE(division,''),
		       scope_limit, log_position, is_live, depth
		FROM officers WHERE delegate_did = $1 ORDER BY log_position DESC LIMIT 1
	`, officerDID).Scan(
		&o.DelegateDID, &o.SignerDID, &o.Role, &o.Division,
		&o.ScopeLimit, &o.LogPosition, &o.IsLive, &o.Depth,
	)
	if err != nil {
		writeError(w, http.StatusNotFound, "officer not found")
		return
	}

	writeJSON(w, http.StatusOK, o)
}
