package courts

import (
	"encoding/json"
	"net/http"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// SealedFilterMiddleware checks whether the requested case is sealed or expunged.
// If sealed: returns 403. If expunged: returns 404. Otherwise: passes through.
func SealedFilterMiddleware(db *common.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			docket := r.PathValue("docket")
			if docket == "" {
				next.ServeHTTP(w, r)
				return
			}

			if db == nil {
				next.ServeHTTP(w, r)
				return
			}

			var sealed, expunged bool
			err := db.QueryRowContext(r.Context(),
				`SELECT sealed, expunged FROM cases WHERE docket_number = $1`,
				docket,
			).Scan(&sealed, &expunged)

			if err != nil {
				// Case not found in Postgres — let handler deal with it.
				next.ServeHTTP(w, r)
				return
			}

			if expunged {
				writeError(w, http.StatusNotFound, "case not found")
				return
			}

			if sealed {
				writeError(w, http.StatusForbidden, "case is sealed")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ─── JSON response helpers ──────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
