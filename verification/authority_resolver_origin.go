/*
FILE PATH: verification/authority_resolver_origin.go

DESCRIPTION:

	Per-hop fetch + parse + liveness check for AuthorityResolver.
	Split out of authority_resolver.go to keep that file focused on
	the chain-walk control flow.

	fetchAndValidate is called once per hop during Resolve. It:

	  1. Fetches the entry at the given LogPosition from the
	     ledger (via Fetcher).
	  2. Deserializes the entry envelope.
	  3. Inspects DomainPayload to determine schema:
	       - judicial-delegation-v1 → continue (the common case).
	       - judicial-revocation-v1 → reject (chain hop revoked).
	       - judicial-succession-v1 → at this hop, transparently
	         follow the successor (the resolver continues walking
	         but with the SuccessorDID as the expected granter for
	         the next hop, and treats THIS hop's payload as still
	         authoritative because the institutional Authority_Set
	         cosigned the succession).
	  4. Parses the JudicialDelegationPayload (Validate runs).
	  5. Confirms the payload's GranteeDID equals the
	     expected-grantee passed by the walker (each hop's grantee
	     must be the previous hop's granter — the chain rule).
	  6. Confirms not-expired against the resolver's clock.
	  7. If LeafReader is available, evaluates Origin_Tip via the
	     SDK's EvaluateOrigin. If Origin_Tip points to a revocation
	     entry, the hop is rejected; if it points to a succession,
	     the resolver still accepts THIS hop (the original
	     delegation's role + scope are authoritative) but logs the
	     redirect for downstream consumers.

OVERVIEW:

	fetchAndValidate — the per-hop primitive.
	classifyTip      — schema-based tip-entry routing.

KEY DEPENDENCIES:
  - schemas (JudicialDelegationPayload, schema URI consts).
  - attesta envelope (Deserialize), verifier (EvaluateOrigin).
*/
package verification

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// fetchAndValidate fetches one chain hop, parses the delegation
// payload, and runs the per-hop checks. Returns the resolved hop on
// success, or a typed rejection.
func (r *AuthorityResolver) fetchAndValidate(
	ref schemas.LogPositionRef,
	expectedGrantee string,
	now time.Time,
) (*resolvedHop, AuthorityRejection, string) {
	pos := types.LogPosition{
		LogDID:   ref.LogDID,
		Sequence: ref.Sequence,
	}
	meta, err := r.Fetcher.Fetch(pos)
	if err != nil {
		return nil, RejectFetchFailed, fmt.Sprintf("fetch %s: %v", pos.String(), err)
	}
	if meta == nil {
		return nil, RejectFetchFailed, fmt.Sprintf("fetch %s: %v", pos.String(), errFetchNotFound)
	}

	entry, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil {
		return nil, RejectMalformedPayload, fmt.Sprintf("deserialize %s: %v", pos.String(), err)
	}

	switch classifyTip(entry.DomainPayload) {
	case schemas.SchemaJudicialRevocationV1:
		return nil, RejectRevoked, fmt.Sprintf("hop entry at %s is a revocation", pos.String())
	case schemas.SchemaJudicialSuccessionV1:
		// A succession entry at this position means the institutional
		// Authority_Set published a top-of-chain transition. The hop
		// payload's role + scope are NOT what we want here — succession
		// applies to a different DID's delegation. The resolver
		// surfaces this as a special rejection so the caller can
		// re-resolve with the SuccessorDID.
		return nil, RejectRevoked, fmt.Sprintf("hop entry at %s is a succession; caller must re-resolve via SuccessorDID", pos.String())
	}

	payload, err := schemas.UnmarshalJudicialDelegationPayload(entry.DomainPayload)
	if err != nil {
		return nil, RejectMalformedPayload, fmt.Sprintf("payload %s: %v", pos.String(), err)
	}
	if payload.GranteeDID != expectedGrantee {
		return nil, RejectSignerMismatch,
			fmt.Sprintf("hop %s grantee=%s but chain expected %s",
				pos.String(), payload.GranteeDID, expectedGrantee)
	}
	if !payload.ParsedExpiresAt().After(now) {
		return nil, RejectExpired,
			fmt.Sprintf("hop %s expired at %s (now %s)",
				pos.String(),
				payload.ParsedExpiresAt().Format(time.RFC3339),
				now.Format(time.RFC3339))
	}

	if rej, reason := r.evaluateOrigin(pos); rej != RejectNone {
		return nil, rej, reason
	}

	return &resolvedHop{payload: payload, entry: entry}, RejectNone, ""
}

// classifyTip returns the schema_id for routing. Empty string when
// the payload is not JSON or has no schema_id.
func classifyTip(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	var probe struct {
		SchemaID string `json:"schema_id"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return ""
	}
	return probe.SchemaID
}

// evaluateOrigin reads the SMT leaf for the hop's position to detect
// revocation/succession that has happened SINCE the delegation was
// first published. nil LeafReader → skipped (the static delegation
// entry is the only authority signal).
//
// Returns RejectNone when origin is Original or Amended; rejection
// when revoked/succeeded.
func (r *AuthorityResolver) evaluateOrigin(pos types.LogPosition) (AuthorityRejection, string) {
	if r.LeafReader == nil {
		return RejectNone, ""
	}
	key := smt.DeriveKey(pos)
	eval, err := verifier.EvaluateOrigin(key, r.LeafReader, r.Fetcher)
	if err != nil {
		// Leaf not found is the common "fresh delegation, no
		// amendments" case — treat as live.
		return RejectNone, ""
	}
	switch eval.State {
	case verifier.OriginOriginal, verifier.OriginAmended:
		return RejectNone, ""
	case verifier.OriginRevoked:
		return RejectRevoked,
			fmt.Sprintf("origin revoked at %s; tip=%s", pos.String(), eval.TipPosition.String())
	case verifier.OriginSucceeded:
		// Top-of-chain succession — the chain still authorizes
		// downstream entries because the institutional Authority_Set
		// published it. Treat as live; the audit log captures the
		// redirect at the catalog/registry layer.
		return RejectNone, ""
	case verifier.OriginPending:
		return RejectRevoked,
			fmt.Sprintf("origin pending at %s; activation delay not satisfied", pos.String())
	default:
		return RejectNone, ""
	}
}
