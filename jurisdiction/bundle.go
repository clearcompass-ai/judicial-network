/*
FILE PATH: jurisdiction/bundle.go

DESCRIPTION:

	Bundle — the per-jurisdiction policy contract. Every court /
	consortium / sub-network ships ONE Bundle implementation that
	exposes five closed-set surfaces the verifier depends on:

	  RoleCatalog            — Signer role definitions and
	                           delegation rules (judge, magistrate,
	                           court_clerk, court_reporter, …).
	  CosignaturePolicy      — closed-set cosignature mix per
	                           event_type (AllowedFilerRoles,
	                           RequiredSignerRoles, IntraExchangeOnly).
	  PrerequisitePolicy     — closed-set vocabulary + per-event
	                           prereq rules (RequiredAncestor /
	                           RequiredAuthority).
	  AuthorityChainResolver — per-jurisdiction delegation chain
	                           walker. Davidson chains validate
	                           against Davidson's catalog only;
	                           Shelby's against Shelby's. Trial
	                           counties wire NoAuthorityChainResolver
	                           at boot until the production resolver
	                           is plugged in.
	  AppellateVocabulary    — per-jurisdiction closed sets for
	                           appellate event payload enums (opinion
	                           type, participation role, disposition
	                           outcome, review type). Trial-only
	                           exchanges return EmptyAppellateVocab.

	Plus the institutional anchor:

	  ExchangeDID            — the institutional DID this Bundle's
	                           rules are scoped to. Convention:
	                             State:   did:web:state:tn:<court-id>
	                             Federal: did:web:fed:<level>:<court-id>
	                           The cosig verifier uses this for
	                           IntraExchangeOnly; the registry uses
	                           it as the lookup key.

	Why an interface, not a struct: enables future loading via Go
	plugins (v3 roadmap), allows test doubles, and keeps the core
	packages free of any jurisdiction-specific types. Concrete impls
	live under deployments/<framework>/<court>/rules/.

	Composition rule: a Bundle's three vocabulary policies (cosig,
	prereq, appellate) SHOULD share their closed-set event_type
	namespace. Validate() exists to surface mismatches at boot
	rather than at first verification.

OVERVIEW:

	Bundle      — interface (6 methods).
	Validate    — boot-time consistency check.
	Provider    — factory function type for v3 plugin loading.
	Sentinels.

KEY DEPENDENCIES:
  - jurisdiction/appellate_vocab.go         (AppellateVocab).
  - jurisdiction/authority_chain_resolver.go (AuthorityChainResolver).
  - schemas/role_catalog.go                 (RoleCatalog).
  - policy/cosignature_mix.go               (CosignatureMixPolicy).
  - prerequisites/policy.go                 (Policy).
*/
package jurisdiction

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// Bundle is the per-jurisdiction policy surface. Implementations
// MUST be safe for concurrent use; the registry hands the same
// instance to every caller.
type Bundle interface {
	// ExchangeDID is the institutional DID this Bundle's rules
	// govern. Acts as the registry key and the IntraExchangeOnly
	// gate's reference value. Required, non-empty.
	ExchangeDID() string

	// RoleCatalog exposes the closed-set Tier 1 (Signer) role
	// definitions plus delegation rules for this jurisdiction.
	RoleCatalog() schemas.RoleCatalog

	// CosignaturePolicy exposes the closed-set cosignature mix
	// (per event_type, AllowedFilerRoles, RequiredSignerRoles,
	// MinSignerCosigners, IntraExchangeOnly, RequiredCredentials).
	CosignaturePolicy() policy.CosignatureMixPolicy

	// PrerequisitePolicy exposes the closed-set vocabulary +
	// per-event prerequisite rules (RequiredAncestor /
	// RequiredAuthority).
	PrerequisitePolicy() prerequisites.Policy

	// AuthorityChainResolver returns the per-jurisdiction
	// delegation chain walker. Each Bundle returns ITS resolver;
	// chains are validated against THIS jurisdiction's RoleCatalog
	// only. Required, non-nil. Trial bundles may return
	// NoAuthorityChainResolver() until the production wiring lands.
	AuthorityChainResolver() AuthorityChainResolver

	// AppellateVocabulary returns the closed-set enums this
	// jurisdiction accepts on appellate event payloads (opinion
	// type, participation role, disposition outcome, review type).
	// Trial-only exchanges return EmptyAppellateVocab(). Required,
	// non-nil.
	AppellateVocabulary() AppellateVocab
}

// Provider is a Bundle factory. Used by the v3 plugin path:
// `plugin.Open(...).Lookup("Provider")` returns a Provider symbol
// that, when called, yields the jurisdiction's Bundle.
type Provider func() (Bundle, error)

// ─── Sentinels ──────────────────────────────────────────────────────

var (
	// ErrInvalidBundle signals a Bundle that fails Validate.
	ErrInvalidBundle = errors.New("jurisdiction: invalid bundle")

	// ErrVocabularyMismatch signals that the cosignature and
	// prerequisite policies disagree on which event_types belong
	// in the jurisdiction's closed-set vocabulary.
	ErrVocabularyMismatch = errors.New("jurisdiction: vocabulary mismatch between cosignature and prerequisite policies")
)

// ─── Validate ───────────────────────────────────────────────────────

// Validate runs structural checks on a Bundle:
//
//   - ExchangeDID non-empty.
//   - RoleCatalog non-nil and lists at least one role.
//   - CosignaturePolicy + PrerequisitePolicy non-nil.
//   - Every event_type in CosignaturePolicy must be known to
//     PrerequisitePolicy. The reverse is NOT required: the
//     prerequisite policy may include bootstrap events
//     (case_initiated, hearing) that have no cosignature mix.
//
// Validate is idempotent and safe to call at boot. The registry
// invokes it before accepting a Bundle.
func Validate(b Bundle) error {
	if b == nil {
		return fmt.Errorf("%w: nil bundle", ErrInvalidBundle)
	}
	if b.ExchangeDID() == "" {
		return fmt.Errorf("%w: empty ExchangeDID", ErrInvalidBundle)
	}
	cat := b.RoleCatalog()
	if cat == nil {
		return fmt.Errorf("%w: nil RoleCatalog", ErrInvalidBundle)
	}
	if len(cat.List()) == 0 {
		return fmt.Errorf("%w: empty RoleCatalog", ErrInvalidBundle)
	}
	cp := b.CosignaturePolicy()
	if cp == nil {
		return fmt.Errorf("%w: nil CosignaturePolicy", ErrInvalidBundle)
	}
	pp := b.PrerequisitePolicy()
	if pp == nil {
		return fmt.Errorf("%w: nil PrerequisitePolicy", ErrInvalidBundle)
	}
	// Every cosignature event_type must appear in the prerequisite
	// vocabulary; otherwise an entry could pass cosig but fail the
	// vocabulary gate (or vice versa).
	for _, evt := range cp.List() {
		if !pp.KnowsEventType(evt.EventType) {
			return fmt.Errorf("%w: cosig event %q not in prereq vocabulary",
				ErrVocabularyMismatch, evt.EventType)
		}
	}
	if b.AuthorityChainResolver() == nil {
		return fmt.Errorf("%w: nil AuthorityChainResolver", ErrInvalidBundle)
	}
	if b.AppellateVocabulary() == nil {
		return fmt.Errorf("%w: nil AppellateVocabulary", ErrInvalidBundle)
	}
	return nil
}
