package courts

import (
	"net/http"
	"time"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// PublishDocket handles POST /v1/docket.
// Submits BuildCommentary with daily assignment schema.
func (s *Server) PublishDocket(w http.ResponseWriter, r *http.Request) {
	var req common.DocketRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Date == "" {
		req.Date = time.Now().Format("2006-01-02")
	}
	if len(req.Assignments) == 0 {
		writeError(w, http.StatusBadRequest, "at least one assignment required")
		return
	}

	// Convert to exchange payload.
	var assignments []map[string]any
	for _, a := range req.Assignments {
		assignments = append(assignments, map[string]any{
			"judge_did":  a.JudgeDID,
			"courtrooms": a.Courtrooms,
			"case_types": a.CaseTypes,
		})
	}

	signerDID := SignerDIDFromContext(r.Context())
	result, err := s.exchange.SubmitCommentary(signerDID, s.cfg.CasesLogDID, map[string]any{
		"schema_ref":      "tn-daily-assignment-v1",
		"assignment_date": req.Date,
		"court_did":       s.cfg.CourtDID,
		"assignments":     assignments,
		"published_at":    time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "exchange: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"docket_position": result.Position,
		"date":            req.Date,
	})
}

// GetDocket handles GET /v1/docket/{date}.
func (s *Server) GetDocket(w http.ResponseWriter, r *http.Request) {
	date := r.PathValue("date")

	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	rows, err := s.db.QueryContext(r.Context(), `
		SELECT judge_did, courtrooms, case_types, log_position, COALESCE(division,'')
		FROM assignments
		WHERE assignment_date = $1::date AND superseded_by IS NULL
		ORDER BY judge_did ASC
	`, date)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()

	var assignments []map[string]any
	for rows.Next() {
		var judgeDID, division string
		var courtrooms, caseTypes []string
		var pos uint64
		rows.Scan(&judgeDID, &courtrooms, &caseTypes, &pos, &division)
		assignments = append(assignments, map[string]any{
			"judge_did":    judgeDID,
			"courtrooms":  courtrooms,
			"case_types":  caseTypes,
			"log_position": pos,
			"division":    division,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"date":        date,
		"assignments": assignments,
	})
}

// Reassign handles POST /v1/docket/reassign.
func (s *Server) Reassign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Date        string   `json:"date"`
		FromJudge   string   `json:"from_judge"`
		ToJudge     string   `json:"to_judge"`
		Courtrooms  []string `json:"courtrooms"`
		Reason      string   `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Date == "" {
		req.Date = time.Now().Format("2006-01-02")
	}

	signerDID := SignerDIDFromContext(r.Context())
	result, err := s.exchange.SubmitCommentary(signerDID, s.cfg.CasesLogDID, map[string]any{
		"schema_ref":      "tn-assignment-change-v1",
		"assignment_date": req.Date,
		"change_type":     "reassignment",
		"from_judge":      req.FromJudge,
		"to_judge":        req.ToJudge,
		"courtrooms":      req.Courtrooms,
		"reason":          req.Reason,
		"effective":       time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "exchange: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"reassignment_position": result.Position,
	})
}
