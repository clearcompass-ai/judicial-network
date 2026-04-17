/*
FILE PATH: business/auth/delegation_check.go

DESCRIPTION:
    Authenticates CMS agents and admins via mTLS + on-log delegation.

    1. mTLS handshake → extract DID from client cert SAN
    2. Call verification API: GET /v1/verify/delegation/{logID}/{courtDID}
    3. Find the caller's DID in the delegation tree
    4. Check liveness (delegation not revoked)
    5. Check scope_limit in Domain Payload includes required scope

    No tokens. No sessions. No RBAC tables. The log IS the
    authorization database. Revocation is BuildRevocation on-log.

    This is the Web3 model adapted for institutional governance:
    the court's delegation chain on the officers log determines
    who can do what. The business API just reads the chain.

KEY DEPENDENCIES:
    - judicial-network/exchange/auth: ExtractDIDFromRequest (mTLS)
    - judicial-network/api: verification service (delegation walk)
*/
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	exchangeAuth "github.com/clearcompass-ai/judicial-network/exchange/auth"
)

// DelegationAuthConfig configures the delegation auth middleware.
type DelegationAuthConfig struct {
	VerificationEndpoint string
	OfficersLogID        string
	CourtDID             string
}

// DelegationAuth is middleware that verifies mTLS + on-log delegation.
type DelegationAuth struct {
	cfg DelegationAuthConfig
}

// NewDelegationAuth creates the delegation auth middleware.
func NewDelegationAuth(cfg DelegationAuthConfig) *DelegationAuth {
	return &DelegationAuth{cfg: cfg}
}

// RequireScope wraps a handler, requiring the caller to have a live
// delegation with the specified scope in their Domain Payload.
func (da *DelegationAuth) RequireScope(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Step 1: Extract DID from client cert SAN.
		callerDID := exchangeAuth.ExtractDIDFromRequest(r)
		if callerDID == "" {
			http.Error(w, "mTLS required: no client certificate with DID SAN", http.StatusUnauthorized)
			return
		}

		// Step 2: Check delegation on-log via verification API.
		delegations, err := da.fetchDelegations()
		if err != nil {
			http.Error(w, "delegation verification unavailable", http.StatusServiceUnavailable)
			return
		}

		// Step 3: Find caller's delegation in the tree.
		delegation, found := findDelegation(delegations, callerDID)
		if !found {
			http.Error(w, "no live delegation for "+callerDID, http.StatusForbidden)
			return
		}

		// Step 4: Check liveness.
		if !delegation.Live {
			http.Error(w, "delegation revoked for "+callerDID, http.StatusForbidden)
			return
		}

		// Step 5: Check scope.
		if !hasScope(delegation.DomainPayload, scope) {
			http.Error(w, fmt.Sprintf("scope '%s' not in delegation for %s", scope, callerDID), http.StatusForbidden)
			return
		}

		// Attach caller DID to context.
		ctx := exchangeAuth.WithSignerDID(r.Context(), callerDID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (da *DelegationAuth) fetchDelegations() (*DelegationTree, error) {
	url := fmt.Sprintf("%s/v1/verify/delegation/%s/%s",
		da.cfg.VerificationEndpoint,
		da.cfg.OfficersLogID,
		da.cfg.CourtDID,
	)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tree DelegationTree
	if err := json.Unmarshal(body, &tree); err != nil {
		return nil, err
	}
	return &tree, nil
}

// DelegationTree mirrors the verification API response.
type DelegationTree struct {
	Delegations []DelegationHop `json:"delegations"`
}

// DelegationHop is one node in the delegation tree.
type DelegationHop struct {
	DelegateDID   string `json:"delegate_did"`
	DelegatorDID  string `json:"delegator_did"`
	Depth         int    `json:"depth"`
	Live          bool   `json:"live"`
	LogPosition   uint64 `json:"log_position"`
	DomainPayload any    `json:"domain_payload"`
}

func findDelegation(tree *DelegationTree, did string) (*DelegationHop, bool) {
	for i, hop := range tree.Delegations {
		if hop.DelegateDID == did {
			return &tree.Delegations[i], true
		}
	}
	return nil, false
}

func hasScope(domainPayload any, requiredScope string) bool {
	m, ok := domainPayload.(map[string]any)
	if !ok {
		return false
	}

	scopeLimit, ok := m["scope_limit"]
	if !ok {
		return true // no scope_limit means unrestricted
	}

	switch sl := scopeLimit.(type) {
	case []any:
		for _, s := range sl {
			if str, ok := s.(string); ok && str == requiredScope {
				return true
			}
		}
	case string:
		return sl == requiredScope || sl == "*"
	}

	return false
}

// WithSignerDID re-exports for business package convenience.
func WithSignerDID(ctx context.Context, did string) context.Context {
	return exchangeAuth.WithSignerDID(ctx, did)
}

// extractScope is shared with domain payload parsing in handlers
func extractStringSlice(payload any, field string) []string {
	m, ok := payload.(map[string]any)
	if !ok {
		return nil
	}
	v, ok := m[field]
	if !ok {
		return nil
	}
	sl, ok := v.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(sl))
	for _, item := range sl {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// MatchesDID checks if a DID matches, handling case-insensitive comparison.
func MatchesDID(a, b string) bool {
	return strings.EqualFold(a, b)
}
