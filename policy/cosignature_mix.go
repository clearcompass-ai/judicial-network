/*
FILE PATH: policy/cosignature_mix.go

DESCRIPTION:
    Phase 3C cosignature-mix policy module. The data-driven answer
    to the v1.4 Event Dictionary's developer flags:

      Flag #1 — Tier 2 cosignature mix.
                Which ActorSigner role may cosign which event_type
                when filed by which FilerRole.

      Flag #2 — Cross-exchange cosignature validity.
                Whether an event requires INTRA-exchange cosignature
                only (e.g., judicial_appointment) or permits
                CROSS-exchange cosignatures (e.g., case transfers,
                relay attestations).

    The policy is a closed-set table. The verifier
    (verification/cosignature_check.go) calls Lookup(eventType)
    once per entry and reads the rule:

      rule.AllowedFilerRoles    — the capacity.role must be in here
      rule.RequiredSignerRoles  — at least one ActorSigner cosigner
                                  must hold one of these roles
      rule.MinSignerCosigners   — count threshold (default 1)
      rule.IntraExchangeOnly    — Flag #2; if true, every signer
                                  must come from the entry's exchange
      rule.RequiredCredentials  — capacity.credentials must contain
                                  every key (non-empty value)

OVERVIEW:
    CosignatureRule       — the rule struct.
    CosignatureMixPolicy  — interface (Lookup, List).
    InMemoryPolicy        — RWMutex-protected map implementation
                            (methods in cosignature_mix_inmemory.go).
    Sentinel errors and validateRule.

KEY DEPENDENCIES:
    - schemas/capacity.go (FilerRole closed set referenced in
      AllowedFilerRoles).
*/
package policy

import (
	"errors"
	"fmt"
	"sync"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// CosignatureRule is one row of the policy table — the cosignature
// requirements for a single event_type. Stable JSON tags; the
// loader (cosignature_mix_loader.go) round-trips this shape.
type CosignatureRule struct {
	// EventType is the dictionary's snake_case event identifier.
	// Required, unique per policy instance.
	EventType string `json:"event_type"`

	// AllowedFilerRoles lists the FilerRole values that may file
	// this event. Empty means "no filer permitted" — the event is
	// solely an ActorSigner action (e.g. final_judgment, verdict);
	// no Tier 2 cosignature is required and the verifier accepts
	// entries with no filed_by_capacity at all.
	AllowedFilerRoles []schemas.FilerRole `json:"allowed_filer_roles,omitempty"`

	// RequiredSignerRoles names the ActorSigner roles permitted to
	// cosign. OR semantics — at least one cosigner with a role in
	// this list must be present. Required (non-empty) when
	// AllowedFilerRoles is non-empty.
	RequiredSignerRoles []string `json:"required_signer_roles,omitempty"`

	// MinSignerCosigners is the minimum count of ActorSigner
	// cosigners with roles in RequiredSignerRoles. Default 1.
	// Larger values for sensitive events (e.g., 2 for
	// judicial_appointment per Flag #3 once that surface lands).
	MinSignerCosigners int `json:"min_signer_cosigners,omitempty"`

	// IntraExchangeOnly per v1.4 Flag #2. When true, every
	// ActorSigner cosigner must come from the entry's exchange
	// (Header.Destination). When false, cross-exchange cosigners
	// are accepted (used by case_transfer_*, relay_attestation,
	// bulk_historical_import).
	IntraExchangeOnly bool `json:"intra_exchange_only"`

	// RequiredCredentials is the list of credential keys the
	// filer's capacity.credentials map must contain (non-empty).
	// E.g. ["bpr_number", "jurisdiction"] for attorney filings;
	// ["letters_of_administration_ref"] for fiduciary filings.
	RequiredCredentials []string `json:"required_credentials,omitempty"`
}

// PermitsFilerRole reports whether r is in the rule's
// AllowedFilerRoles list. Convenience used by the verifier.
func (r *CosignatureRule) PermitsFilerRole(role schemas.FilerRole) bool {
	for _, allowed := range r.AllowedFilerRoles {
		if allowed == role {
			return true
		}
	}
	return false
}

// PermitsSignerRole reports whether signerRole is in the rule's
// RequiredSignerRoles list (OR semantics).
func (r *CosignatureRule) PermitsSignerRole(signerRole string) bool {
	for _, allowed := range r.RequiredSignerRoles {
		if allowed == signerRole {
			return true
		}
	}
	return false
}

// RequiresFiler reports whether this event MUST carry a
// filed_by_capacity block. False for ActorSigner-only events
// (verdict, final_judgment, judicial_appointment) where no Tier 2
// is involved.
func (r *CosignatureRule) RequiresFiler() bool {
	return len(r.AllowedFilerRoles) > 0
}

// EffectiveMinCosigners returns the minimum count of ActorSigner
// cosigners required for the event:
//
//   - If MinSignerCosigners > 0, use it (explicit threshold).
//     Personnel events like judicial_appointment set this to 2.
//   - Else, if the rule requires a filer (Tier 2 cosignature),
//     default to 1 (the convention for attorney filings).
//   - Else, 0 (pure-signer events like verdict need only the
//     primary signer; no cosignature threshold).
func (r *CosignatureRule) EffectiveMinCosigners() int {
	if r.MinSignerCosigners > 0 {
		return r.MinSignerCosigners
	}
	if r.RequiresFiler() {
		return 1
	}
	return 0
}

// ─── Interface ──────────────────────────────────────────────────────

// CosignatureMixPolicy is the seam between the verifier and the
// rule table. Implementations: InMemoryPolicy (this package);
// future PostgresPolicy / on-log-governed variants if the
// deployment needs them.
type CosignatureMixPolicy interface {
	// Lookup returns the rule for eventType, or ErrRuleNotFound
	// when unknown.
	Lookup(eventType string) (*CosignatureRule, error)

	// List returns all rules in deterministic order (alpha by
	// EventType).
	List() []*CosignatureRule
}

// ─── Sentinel errors ────────────────────────────────────────────────

var (
	// ErrRuleNotFound fires from Lookup when eventType is unknown.
	// Verifier policy: closed-set, unknown events are REJECTED.
	ErrRuleNotFound = errors.New("policy/cosignature_mix: rule not found")

	// ErrInvalidRule fires for missing/malformed fields at Add.
	ErrInvalidRule = errors.New("policy/cosignature_mix: invalid rule")

	// ErrDuplicateRule fires when Add or NewInMemoryPolicy receives
	// two rules with the same EventType.
	ErrDuplicateRule = errors.New("policy/cosignature_mix: duplicate rule")
)

// validateRule runs structural sanity. A rule with no filer roles
// (pure ActorSigner event) is valid — RequiredSignerRoles may be
// empty there. Otherwise the rule must list both filer + signer
// roles.
func validateRule(r CosignatureRule) error {
	if r.EventType == "" {
		return fmt.Errorf("%w: event_type required", ErrInvalidRule)
	}
	for i, fr := range r.AllowedFilerRoles {
		if !fr.IsValid() {
			return fmt.Errorf("%w: event %q allowed_filer_roles[%d] %q not in FilerRole closed set",
				ErrInvalidRule, r.EventType, i, string(fr))
		}
	}
	if r.RequiresFiler() && len(r.RequiredSignerRoles) == 0 {
		return fmt.Errorf("%w: event %q has filer roles but no required_signer_roles",
			ErrInvalidRule, r.EventType)
	}
	for i, sr := range r.RequiredSignerRoles {
		if sr == "" {
			return fmt.Errorf("%w: event %q required_signer_roles[%d] empty",
				ErrInvalidRule, r.EventType, i)
		}
	}
	if r.MinSignerCosigners < 0 {
		return fmt.Errorf("%w: event %q min_signer_cosigners must be >= 0",
			ErrInvalidRule, r.EventType)
	}
	for i, c := range r.RequiredCredentials {
		if c == "" {
			return fmt.Errorf("%w: event %q required_credentials[%d] empty",
				ErrInvalidRule, r.EventType, i)
		}
	}
	return nil
}

// ─── InMemoryPolicy ────────────────────────────────────────────────

// InMemoryPolicy is the default CosignatureMixPolicy. RWMutex-
// protected; safe for concurrent use. Method bodies live in
// cosignature_mix_inmemory.go.
type InMemoryPolicy struct {
	mu    sync.RWMutex
	rules map[string]*CosignatureRule
}

// NewInMemoryPolicy constructs a policy from a slice of rules.
// Rejects duplicates and validates each rule individually.
func NewInMemoryPolicy(rules []CosignatureRule) (*InMemoryPolicy, error) {
	p := &InMemoryPolicy{rules: make(map[string]*CosignatureRule, len(rules))}
	for _, r := range rules {
		if err := validateRule(r); err != nil {
			return nil, err
		}
		if _, dup := p.rules[r.EventType]; dup {
			return nil, fmt.Errorf("%w: event_type=%s", ErrDuplicateRule, r.EventType)
		}
		copyRule := r
		p.rules[r.EventType] = &copyRule
	}
	return p, nil
}

// Static check that InMemoryPolicy satisfies the interface.
var _ CosignatureMixPolicy = (*InMemoryPolicy)(nil)
