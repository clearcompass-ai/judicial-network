package courts

import (
	"encoding/json"
	"net/http"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// CreateCase handles POST /v1/cases.
// Submits a BuildRootEntity to the exchange.
func (s *Server) CreateCase(w http.ResponseWriter, r *http.Request) {
	var req common.CreateCaseRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.DocketNumber == "" || req.CaseType == "" {
		writeError(w, http.StatusBadRequest, "docket_number and case_type required")
		return
	}

	signerDID := SignerDIDFromContext(r.Context())
	result, err := s.exchange.SubmitRootEntity(signerDID, s.cfg.CasesLogDID, map[string]any{
		"docket_number": req.DocketNumber,
		"case_type":     req.CaseType,
		"division":      req.Division,
		"filed_date":    req.FiledDate,
		"status":        "active",
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "exchange: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"docket_number": req.DocketNumber,
		"log_position":  result.Position,
	})
}

// GetCase handles GET /v1/cases/{docket}.
// Reads from Postgres aggregator.
func (s *Server) GetCase(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")

	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	var c common.CaseRecord
	err := s.db.QueryRowContext(r.Context(), `
		SELECT id, docket_number, case_type, COALESCE(division,''), status,
		       COALESCE(filed_date::text,''), court_did, log_did, log_position,
		       signer_did, sealed, expunged, COALESCE(assigned_judge,'')
		FROM cases WHERE docket_number = $1
	`, docket).Scan(
		&c.ID, &c.DocketNumber, &c.CaseType, &c.Division, &c.Status,
		&c.FiledDate, &c.CourtDID, &c.LogDID, &c.LogPosition,
		&c.SignerDID, &c.Sealed, &c.Expunged, &c.AssignedJudge,
	)
	if err != nil {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}

	writeJSON(w, http.StatusOK, c)
}

// GetCaseTimeline handles GET /v1/cases/{docket}/timeline.
func (s *Server) GetCaseTimeline(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")

	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	var caseID int64
	err := s.db.QueryRowContext(r.Context(),
		`SELECT id FROM cases WHERE docket_number = $1`, docket,
	).Scan(&caseID)
	if err != nil {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}

	rows, err := s.db.QueryContext(r.Context(), `
		SELECT event_type, log_position, signer_did, COALESCE(authority_path,''),
		       COALESCE(payload_summary::text,'{}'), COALESCE(log_time::text,'')
		FROM case_events WHERE case_id = $1 ORDER BY log_position ASC
	`, caseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()

	var events []map[string]any
	for rows.Next() {
		var eventType, signerDID, authorityPath, payloadStr, logTime string
		var logPos uint64
		rows.Scan(&eventType, &logPos, &signerDID, &authorityPath, &payloadStr, &logTime)

		var payload map[string]any
		json.Unmarshal([]byte(payloadStr), &payload)

		events = append(events, map[string]any{
			"event_type":     eventType,
			"log_position":   logPos,
			"signer_did":     signerDID,
			"authority_path": authorityPath,
			"payload":        payload,
			"log_time":       logTime,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"docket":   docket,
		"timeline": events,
	})
}

// UpdateCaseStatus handles PATCH /v1/cases/{docket}/status.
func (s *Server) UpdateCaseStatus(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")

	var req common.UpdateStatusRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	casePos, err := s.lookupCasePosition(r, docket)
	if err != nil {
		writeError(w, http.StatusNotFound, "case not found")
		return
	}

	signerDID := SignerDIDFromContext(r.Context())
	result, err := s.exchange.SubmitAmendment(signerDID, s.cfg.CasesLogDID, casePos, map[string]any{
		"status": req.Status,
		"reason": req.Reason,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "exchange: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"log_position": result.Position})
}

// TransferCase handles POST /v1/cases/{docket}/transfer.
func (s *Server) TransferCase(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")

	var req struct {
		DestinationCourtDID string `json:"destination_court_did"`
		Reason              string `json:"reason"`
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

	signerDID := SignerDIDFromContext(r.Context())
	result, err := s.exchange.SubmitAmendment(signerDID, s.cfg.CasesLogDID, casePos, map[string]any{
		"status":               "transferred",
		"transfer_destination": req.DestinationCourtDID,
		"reason":               req.Reason,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "exchange: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"log_position": result.Position,
		"transfer_ref": req.DestinationCourtDID,
	})
}

// lookupCasePosition finds the log position for a docket number.
func (s *Server) lookupCasePosition(r *http.Request, docket string) (uint64, error) {
	if s.db == nil {
		return 0, http.ErrNotSupported
	}
	var pos uint64
	err := s.db.QueryRowContext(r.Context(),
		`SELECT log_position FROM cases WHERE docket_number = $1`, docket,
	).Scan(&pos)
	return pos, err
}
