/*
FILE PATH: business/middleware/sealed_filter.go

DESCRIPTION:
    Returns uniform 404 for sealed or expunged cases. This is
    judicial POLICY, not protocol. The protocol returns "this entity
    has enforcement entries." This middleware decides what to do
    with that information: hide everything.

    Uses the verification API to check enforcement state, then
    the exchange index to map docket → position.

    Uniform response: sealed and non-existent cases return the
    same 404. An observer cannot distinguish "doesn't exist" from
    "sealed." By design.

KEY DEPENDENCIES:
    - judicial-network/api: verification service (authority check)
    - judicial-network/exchange/index: docket → position mapping
*/
package middleware

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/clearcompass-ai/judicial-network/exchange/index"
)

// SealedFilterConfig configures the sealed filter.
type SealedFilterConfig struct {
	VerificationEndpoint string
	CasesLogID           string
	Index                *index.LogIndex
}

// SealedFilter is middleware that blocks access to sealed/expunged cases.
type SealedFilter struct {
	cfg SealedFilterConfig
}

// NewSealedFilter creates the sealed filter middleware.
func NewSealedFilter(cfg SealedFilterConfig) *SealedFilter {
	return &SealedFilter{cfg: cfg}
}

// Wrap wraps a handler with sealed case filtering.
func (sf *SealedFilter) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		docket := r.PathValue("docket")
		if docket == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Look up docket → positions in the exchange index.
		positions := sf.cfg.Index.Store.LookupDocket(sf.cfg.CasesLogID, docket)
		if len(positions) == 0 {
			// Case not found — same 404 as sealed.
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		// Check the case root (first position) for enforcement state.
		caseRootPos := positions[0]
		if sf.isSealed(caseRootPos) {
			// Uniform 404. No "sealed" indicator.
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (sf *SealedFilter) isSealed(pos uint64) bool {
	url := fmt.Sprintf("%s/v1/verify/authority/%s/%d",
		sf.cfg.VerificationEndpoint,
		sf.cfg.CasesLogID,
		pos,
	)

	resp, err := http.Get(url)
	if err != nil {
		// Fail closed: if verification is down, treat as sealed.
		return true
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return true
	}

	var result struct {
		Authority struct {
			Valid bool `json:"valid"`
		} `json:"authority"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return true
	}

	// Parse the full authority response to check for active
	// sealing or expungement enforcement entries.
	var fullResult map[string]any
	json.Unmarshal(body, &fullResult)

	// Check if authority chain contains enforcement entries
	// with type "sealing" or "expungement" that are active.
	// The verification API returns this in the authority.delegation_hops
	// with enforcement entries flagged.
	return checkEnforcementInResponse(fullResult)
}

func checkEnforcementInResponse(result map[string]any) bool {
	authority, ok := result["authority"].(map[string]any)
	if !ok {
		return false
	}

	hops, ok := authority["delegation_hops"].([]any)
	if !ok {
		return false
	}

	for _, hop := range hops {
		hopMap, ok := hop.(map[string]any)
		if !ok {
			continue
		}

		payload, ok := hopMap["domain_payload"].(map[string]any)
		if !ok {
			continue
		}

		enfType, _ := payload["enforcement_type"].(string)
		if enfType == "sealing" || enfType == "expungement" {
			active, _ := payload["active"].(bool)
			if active {
				return true
			}
		}
	}

	return false
}
