/*
FILE PATH: verification/scope_enforcement.go

DESCRIPTION:
    Domain Path B scope_limit interceptor — the read-side defense
    against the Compromised-Subordinate-Key attack
    (ortholog-sdk/docs/implementation-obligations.md).

THE THREAT MODEL:
    The SDK enforces *cryptographic* authority: a Path B entry's
    delegation chain must be live, unrevoked, and connect the signer
    to a root entity. The SDK does NOT inspect DomainPayload (it is
    opaque by protocol). A compromised subordinate key (e.g., an
    automated scheduler) holding a delegation legally narrowed by
    scope_limit can therefore submit any entry the cryptographic chain
    technically permits — including entries whose target schema is
    explicitly forbidden by the delegation's scope_limit.

THE DEFENSE:
    Walk the same delegation chain the SDK validated cryptographically,
    deserialize each delegation's DomainPayload, intersect the
    scope_limit permissions across the chain, and reject if the
    target entry's SchemaRef is not in the permitted set. A narrower
    scope cannot be widened by a parent.

KEY ARCHITECTURAL DECISIONS:
    - Read-side only. Every consumer of judicial entries (verification
      API, monitoring, foreign courts via cross-log) MUST run this
      check after the SDK's cryptographic verification before treating
      the entry as authoritative. Wiring is in delegation_chain.go.
    - Two scope_limit shapes accepted:
        (a) JSON array  ["case_filing","order"]
        (b) CSV string  "case_filing,order"
      Both are first-class. Empty/missing = unrestricted. This matches
      the existing inconsistency between schemas/court_officer.go
      (string) and tools/common/types.go (array) without a breaking
      schema migration.
    - Comparison is case-insensitive on the schema URI's last segment
      (the schema name). "tn-criminal-case-v1" matches "tn-criminal-
      case-v1"; full URI prefix matches are not supported because the
      payload-side scope_limit values are domain-defined strings, not
      log positions.
    - ErrScopeViolation carries the chain hop, the violating
      delegation's DelegateDID, the target schema, and the permitted
      set so audit logs surface enough context to triage without
      re-fetching.

KEY DEPENDENCIES:
    - ortholog-sdk/types: EntryFetcher, LogPosition.
    - ortholog-sdk/core/envelope: Entry, ControlHeader.
*/
package verification

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// Errors surfaced by the scope enforcer. Stable enum values — audit
// pipelines key on these.
var (
	// ErrScopeNoSchemaRef fires when the target entry has no
	// SchemaRef. Without a schema reference there is nothing to
	// authorize against; reject closed.
	ErrScopeNoSchemaRef = errors.New("scope_enforcement: target entry has no SchemaRef")

	// ErrScopeFetcherNil fires before any work; programmer error.
	ErrScopeFetcherNil = errors.New("scope_enforcement: nil fetcher")

	// ErrScopeDelegationFetchFailed wraps a fetcher error during
	// chain walk. Transient.
	ErrScopeDelegationFetchFailed = errors.New("scope_enforcement: delegation fetch failed")

	// ErrScopeDelegationMalformed fires when a delegation entry's
	// DomainPayload cannot be deserialized.
	ErrScopeDelegationMalformed = errors.New("scope_enforcement: delegation payload malformed")

	// ErrScopeViolation is the canonical "this delegation does not
	// permit this schema" rejection. Carries Hop, DelegateDID,
	// TargetSchema, and PermittedSet.
	ErrScopeViolation = errors.New("scope_enforcement: scope_limit violation")
)

// ScopeViolation enriches ErrScopeViolation with the data the
// rejecting verifier observed. Returned via errors.As; the sentinel
// remains errors.Is-matchable.
type ScopeViolation struct {
	Hop          int      // 0-indexed position in DelegationPointers
	DelegateDID  string   // the subordinate whose delegation was violated
	TargetSchema string   // the schema name extracted from target entry's SchemaRef
	PermittedSet []string // the permitted schema names at this hop
}

func (v *ScopeViolation) Error() string {
	return fmt.Sprintf("%s: hop=%d delegate=%s target_schema=%s permitted=%v",
		ErrScopeViolation.Error(), v.Hop, v.DelegateDID, v.TargetSchema, v.PermittedSet)
}

func (v *ScopeViolation) Is(target error) bool {
	return target == ErrScopeViolation
}

// SchemaRefResolver resolves a SchemaRef LogPosition to the schema's
// canonical name. Domain applications inject this — typically a
// thin wrapper over the operator's QueryByPosition that pulls the
// schema entry, deserializes its parameters, and returns the URI.
//
// For tests and dry-run scenarios the resolver may return a stable
// stub (e.g., "tn-criminal-case-v1") for any position.
type SchemaRefResolver func(types.LogPosition) (string, error)

// ScopeEnforcer holds the dependencies the verifier needs. Construct
// per-request; cheap to allocate.
type ScopeEnforcer struct {
	Fetcher        types.EntryFetcher
	SchemaResolver SchemaRefResolver
}

// VerifyDelegationScope walks the target entry's DelegationPointers,
// extracts each delegation's scope_limit, and verifies the target
// entry's SchemaRef is permitted at every hop. Returns nil iff the
// chain authorizes the target schema; returns *ScopeViolation
// (errors.Is(err, ErrScopeViolation) == true) on the first hop that
// rejects.
//
// Path A and commentary entries (no DelegationPointers) return nil
// without inspecting any payload — the SDK's cryptographic check
// alone authorizes them.
func (s *ScopeEnforcer) VerifyDelegationScope(target *envelope.Entry) error {
	if s.Fetcher == nil {
		return ErrScopeFetcherNil
	}
	if target == nil {
		return errors.New("scope_enforcement: nil target entry")
	}
	// Path A / commentary / new-leaf with no delegation chain — no
	// scope_limit machinery applies. Cryptographic verification at
	// the SDK layer is sufficient.
	if len(target.Header.DelegationPointers) == 0 {
		return nil
	}
	if target.Header.SchemaRef == nil {
		return ErrScopeNoSchemaRef
	}
	if s.SchemaResolver == nil {
		return errors.New("scope_enforcement: nil schema resolver")
	}

	targetSchema, err := s.SchemaResolver(*target.Header.SchemaRef)
	if err != nil {
		return fmt.Errorf("scope_enforcement: resolve target schema: %w", err)
	}
	targetSchema = NormalizeSchemaName(targetSchema)

	for hop, ptr := range target.Header.DelegationPointers {
		meta, err := s.Fetcher.Fetch(ptr)
		if err != nil || meta == nil {
			return fmt.Errorf("%w: hop=%d ptr=%s: %v",
				ErrScopeDelegationFetchFailed, hop, ptr.String(), err)
		}
		delEntry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			return fmt.Errorf("%w: hop=%d: %v", ErrScopeDelegationMalformed, hop, err)
		}
		permitted, err := ExtractScopeLimit(delEntry.DomainPayload)
		if err != nil {
			return fmt.Errorf("%w: hop=%d: %v", ErrScopeDelegationMalformed, hop, err)
		}
		if PermitsAll(permitted) {
			// Empty / unrestricted scope — this hop authorizes any
			// schema, continue to next hop.
			continue
		}
		if !ScopePermits(permitted, targetSchema) {
			delegateDID := ""
			if delEntry.Header.DelegateDID != nil {
				delegateDID = *delEntry.Header.DelegateDID
			}
			return &ScopeViolation{
				Hop:          hop,
				DelegateDID:  delegateDID,
				TargetSchema: targetSchema,
				PermittedSet: append([]string(nil), permitted...),
			}
		}
	}
	return nil
}

// ─── Pure helpers — deterministic, no I/O ───────────────────────────

// NormalizeSchemaName strips any "did:..." prefix and trims/
// lowercases the result. Schema names live in DomainPayload as
// short strings ("tn-criminal-case-v1"); SchemaRef resolves to the
// same short string by convention. Trim+lower is idempotent.
func NormalizeSchemaName(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[i+1:]
	}
	return strings.ToLower(s)
}

// ExtractScopeLimit parses a delegation payload's scope_limit field.
// Accepts both shapes:
//   {"scope_limit": ["case_filing", "order"]}      // array
//   {"scope_limit": "case_filing,order"}            // CSV string
//   {}                                               // missing → unrestricted
//   {"scope_limit": ""}                              // empty string → unrestricted
//   {"scope_limit": []}                              // empty array → unrestricted
//
// Returned slice is normalized: trimmed, lowercased, no empty entries.
// Nil/empty returned slice means "unrestricted" — see PermitsAll.
func ExtractScopeLimit(payload []byte) ([]string, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("scope_enforcement: payload not JSON object: %w", err)
	}
	rawScope, ok := raw["scope_limit"]
	if !ok {
		return nil, nil
	}
	// Try array first.
	var asArray []string
	if err := json.Unmarshal(rawScope, &asArray); err == nil {
		return normalizeNames(asArray), nil
	}
	// Try CSV string.
	var asString string
	if err := json.Unmarshal(rawScope, &asString); err == nil {
		return normalizeNames(strings.Split(asString, ",")), nil
	}
	return nil, fmt.Errorf("scope_enforcement: scope_limit not array or string")
}

func normalizeNames(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		n := NormalizeSchemaName(raw)
		if n == "" {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

// PermitsAll returns true when the permitted set is empty/nil — by
// convention, an unset scope_limit grants the delegation full breadth.
// Domain authors who want narrow scoping populate the slice; the
// invariant "explicit listing is restrictive" matches every other
// access-control system in the protocol.
func PermitsAll(permitted []string) bool {
	return len(permitted) == 0
}

// ScopePermits reports whether `target` is in the (already-normalized)
// permitted set. Returns false on empty permitted ONLY if the caller
// has not first checked PermitsAll — empty here means "explicitly no
// schemas authorized". The conservative read.
func ScopePermits(permitted []string, target string) bool {
	for _, p := range permitted {
		if p == target {
			return true
		}
	}
	return false
}
