package providers

import (
	"encoding/json"
	"net/http"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// BackgroundCheck handles POST /v1/background-check.
// Searches Postgres for all cases involving the subject DID.
// Sealed cases are counted but not disclosed. Expunged cases are invisible.
func (s *Server) BackgroundCheck(w http.ResponseWriter, r *http.Request) {
	var req common.BackgroundCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProviderError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	defer r.Body.Close()

	if req.SubjectDID == "" {
		writeProviderError(w, http.StatusBadRequest, "subject_did required")
		return
	}

	if s.db == nil {
		writeProviderError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	// Query all cases where subject appears in events or payload.
	// In production: join against a parties table or full-text search.
	rows, err := s.db.QueryContext(r.Context(), `
		SELECT DISTINCT c.docket_number, c.case_type, c.status,
		       COALESCE(c.filed_date::text,''), c.court_did,
		       COALESCE(c.division,''), c.sealed, c.expunged
		FROM cases c
		JOIN case_events e ON e.case_id = c.id
		WHERE (e.signer_did = $1 OR e.payload_summary::text ILIKE '%' || $1 || '%')
		  AND c.expunged = FALSE
		ORDER BY c.filed_date DESC NULLS LAST
	`, req.SubjectDID)
	if err != nil {
		writeProviderError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()

	var cases []common.CaseRecord
	sealedCount := 0

	for rows.Next() {
		var c common.CaseRecord
		var sealed, expunged bool
		rows.Scan(&c.DocketNumber, &c.CaseType, &c.Status,
			&c.FiledDate, &c.CourtDID, &c.Division, &sealed, &expunged)

		if sealed {
			sealedCount++
			if !req.IncludeSealed {
				continue
			}
			// Redact sealed case details.
			c.Status = "sealed"
			c.FiledDate = ""
			c.Division = ""
		}

		cases = append(cases, c)
	}

	writeProviderJSON(w, http.StatusOK, common.BackgroundCheckResult{
		SubjectDID:  req.SubjectDID,
		Cases:       cases,
		SealedCount: sealedCount,
	})
}
