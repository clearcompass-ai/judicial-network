package providers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// GetRecord handles GET /v1/records/{docket}.
func (s *Server) GetRecord(w http.ResponseWriter, r *http.Request) {
	docket := r.PathValue("docket")

	if s.db == nil {
		writeProviderError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	var c common.CaseRecord
	var filedDate string
	err := s.db.QueryRowContext(r.Context(), `
		SELECT id, docket_number, case_type, COALESCE(division,''), status,
		       COALESCE(filed_date::text,''), court_did, log_did, log_position,
		       signer_did, sealed, expunged, COALESCE(assigned_judge,'')
		FROM cases WHERE docket_number = $1
	`, docket).Scan(
		&c.ID, &c.DocketNumber, &c.CaseType, &c.Division, &c.Status,
		&filedDate, &c.CourtDID, &c.LogDID, &c.LogPosition,
		&c.SignerDID, &c.Sealed, &c.Expunged,  &c.AssignedJudge,
	)
	if err != nil {
		writeProviderError(w, http.StatusNotFound, "case not found")
		return
	}

	// Expunged: invisible.
	if c.Expunged {
		writeProviderError(w, http.StatusNotFound, "case not found")
		return
	}

	// Sealed: redact sensitive fields.
	if c.Sealed {
		writeProviderJSON(w, http.StatusOK, map[string]any{
			"docket_number": c.DocketNumber,
			"case_type":     c.CaseType,
			"status":        "sealed",
			"court_did":     c.CourtDID,
		})
		return
	}

	c.FiledDate = filedDate

	// Include timeline.
	rows, err := s.db.QueryContext(r.Context(), `
		SELECT event_type, log_position, signer_did, COALESCE(log_time::text,'')
		FROM case_events WHERE case_id = $1 ORDER BY log_position ASC
	`, c.ID)
	if err == nil {
		defer rows.Close()
		var timeline []map[string]any
		for rows.Next() {
			var et, signer, lt string
			var pos uint64
			rows.Scan(&et, &pos, &signer, &lt)
			timeline = append(timeline, map[string]any{
				"event_type":   et,
				"log_position": pos,
				"signer_did":   signer,
				"log_time":     lt,
			})
		}

		writeProviderJSON(w, http.StatusOK, map[string]any{
			"case":     c,
			"timeline": timeline,
		})
		return
	}

	writeProviderJSON(w, http.StatusOK, c)
}

// VerifyEntry handles GET /v1/verify/entry/{courtDID}/{log}/{pos}.
// Proxies to domain verification API with human-readable annotations.
func (s *Server) VerifyEntry(w http.ResponseWriter, r *http.Request) {
	logID := r.PathValue("log")
	posStr := r.PathValue("pos")

	pos, err := strconv.ParseUint(posStr, 10, 64)
	if err != nil {
		writeProviderError(w, http.StatusBadRequest, "invalid position")
		return
	}

	origin, err := s.verify.VerifyOrigin(logID, pos)
	if err != nil {
		writeProviderError(w, http.StatusBadGateway, "verify: "+err.Error())
		return
	}

	authority, _ := s.verify.VerifyAuthority(logID, pos)

	writeProviderJSON(w, http.StatusOK, map[string]any{
		"origin_evaluation":    origin,
		"authority_evaluation": authority,
		"human_summary": fmt.Sprintf("Entry at %s position %d verified", logID, pos),
	})
}

// VerifyOfficer handles GET /v1/verify/delegation/{courtDID}/{officerDID}.
func (s *Server) VerifyOfficer(w http.ResponseWriter, r *http.Request) {
	officerDID := r.PathValue("officerDID")

	if s.db == nil {
		writeProviderError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	var o common.OfficerRecord
	err := s.db.QueryRowContext(r.Context(), `
		SELECT delegate_did, signer_did, COALESCE(role,''), COALESCE(division,''),
		       log_position, is_live, depth
		FROM officers WHERE delegate_did = $1 ORDER BY log_position DESC LIMIT 1
	`, officerDID).Scan(
		&o.DelegateDID, &o.SignerDID, &o.Role, &o.Division,
		&o.LogPosition, &o.IsLive, &o.Depth,
	)
	if err != nil {
		writeProviderError(w, http.StatusNotFound, "officer not found")
		return
	}

	// Verify delegation chain via domain API.
	chainResult, _ := s.verify.VerifyDelegation(s.cfg.OfficersLogDID, o.LogPosition)

	writeProviderJSON(w, http.StatusOK, map[string]any{
		"officer":     o,
		"chain_valid": chainResult != nil,
		"chain":       chainResult,
	})
}
