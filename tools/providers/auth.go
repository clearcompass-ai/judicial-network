package providers

import (
	"encoding/json"
	"net/http"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// APIKeyMiddleware validates the API key from the configured header.
// In production: validate against a key store. Here: accept any non-empty key.
func APIKeyMiddleware(cfg common.Config) func(http.Handler) http.Handler {
	header := cfg.ProviderAPIKeyHeader
	if header == "" {
		header = "X-API-Key"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get(header)
			if key == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "API key required in " + header + " header",
				})
				return
			}

			// TODO: Validate key against key store.
			// TODO: Rate limiting per key.
			// TODO: Track usage for billing.

			next.ServeHTTP(w, r)
		})
	}
}
