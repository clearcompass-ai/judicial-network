package providers

import (
	"encoding/json"
	"net/http"
)

// SearchRecords handles GET /v1/records/search?q=&type=&from=&to=&court=
func (s *Server) SearchRecords(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeProviderError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	q := r.URL.Query().Get("q")
	caseType := r.URL.Query().Get("type")
	fromDate := r.URL.Query().Get("from")
	toDate := r.URL.Query().Get("to")
	courtDID := r.URL.Query().Get("court")
	limit := 50

	// Build query dynamically.
	query := `
		SELECT docket_number, case_type, COALESCE(division,''), status,
		       COALESCE(filed_date::text,''), court_did, sealed
		FROM cases WHERE expunged = FALSE
	`
	var args []any
	argN := 1

	if q != "" {
		query += ` AND docket_number ILIKE '%' || $` + itoa(argN) + ` || '%'`
		args = append(args, q)
		argN++
	}
	if caseType != "" {
		query += ` AND case_type = $` + itoa(argN)
		args = append(args, caseType)
		argN++
	}
	if fromDate != "" {
		query += ` AND filed_date >= $` + itoa(argN) + `::date`
		args = append(args, fromDate)
		argN++
	}
	if toDate != "" {
		query += ` AND filed_date <= $` + itoa(argN) + `::date`
		args = append(args, toDate)
		argN++
	}
	if courtDID != "" {
		query += ` AND court_did = $` + itoa(argN)
		args = append(args, courtDID)
		argN++
	}

	query += ` ORDER BY filed_date DESC NULLS LAST LIMIT $` + itoa(argN)
	args = append(args, limit)

	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeProviderError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()

	var results []map[string]any
	for rows.Next() {
		var docket, ct, division, status, filedDate, court string
		var sealed bool
		rows.Scan(&docket, &ct, &division, &status, &filedDate, &court, &sealed)

		record := map[string]any{
			"docket_number": docket,
			"case_type":     ct,
			"division":      division,
			"court_did":     court,
		}

		if sealed {
			record["status"] = "sealed"
		} else {
			record["status"] = status
			record["filed_date"] = filedDate
		}

		results = append(results, record)
	}

	writeProviderJSON(w, http.StatusOK, map[string]any{
		"results": results,
		"count":   len(results),
	})
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

func writeProviderJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeProviderError(w http.ResponseWriter, status int, msg string) {
	writeProviderJSON(w, status, map[string]string{"error": msg})
}
