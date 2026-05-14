/*
FILE PATH: verification/attestation_policy_resolver.go

DESCRIPTION:

	JN seam for attesta v1.3.0's schema-anchored attestation policy
	mechanism. Bridges two new wire fields:

	  - ControlHeader.AttestationPolicyName *string (envelope side)
	    Names which policy the entry adopts; resolved against the
	    entry's Schema_Ref.

	  - SchemaParameters.AttestationPolicies []types.AttestationPolicy
	    The schema's declared policy set (joint-order, en-banc,
	    sealing-supervisor, board-attest, advisory).

	A v1.3.0 entry's adopted policy is the result of two pointer
	follows: read entry.Header.AttestationPolicyName, resolve the
	schema, and look up the policy by name on the resolved
	SchemaParameters. This file performs that resolution and
	composes it with the v1.2.0 attestation.VerifyEntryAttestationPolicy
	composite so admission and read-side verification call one
	function instead of three.

	# SCOPE OF THIS COMMIT (v1.3.0 PICKUP)

	This file does NOT yet wire the admission gate. PR B's job is to
	pick up the v1.3.0 wire fields in a focused, reviewable seam;
	PR D wires the admission middleware that calls
	VerifyEntryAttestationPolicyFromSchema for every incoming entry
	at the api/middleware layer.

	# RELATIONSHIP TO EXISTING JN VERIFIERS

	verification/cosignature_check.go enforces JN's v1.4 Event-
	Dictionary intra-entry signature mix (one entry, N inline
	signatures, role/exchange/threshold). It is NOT the SDK
	attestation policy mechanism; the two coexist (see the doc
	header on cosignature_check.go for the disambiguation).

	verification/attestation_check.go enforces JN's tn-key-
	attestation-v1 temporal-lookup pattern ("what was the
	institution-witnessed key custody mode for entity X at time
	T?"). It is also NOT the SDK attestation policy mechanism.

	This file is the SDK-attestation seam. Use it for multi-
	attester filings: concurring opinions, en-banc panels,
	Board cosignatures on delegations, sealing-supervisor
	concurrences. The attesters sign their OWN entries (each
	carries Header.CosignatureOf pointing at the primary); the
	primary's Header.AttestationPolicyName names the rule.

TRUST ALIGNMENT:

	SDK Principle 11 (Cryptographic Domain Separation): the
	policy name participates in the canonical hash of the primary
	entry (v1.3.0 CHANGELOG: "AttestationPolicyName ... participates
	in the canonical hash — an entry's identity commits to its
	policy attribution"). A hostile peer cannot post-hoc relabel
	an entry to adopt a more permissive policy without
	invalidating its signature.

KEY DEPENDENCIES:
  - attesta/attestation v1.3.0: VerifyEntryAttestationPolicy,
    SignatureVerifier, DelegationResolver, PolicyReport
  - attesta/core/envelope: Entry, ControlHeader.AttestationPolicyName
  - attesta/types: AttestationPolicy, SchemaParameters,
    FindAttestationPolicy, ErrDuplicatePolicyName
*/
package verification

import (
	"context"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"
)

// ErrAttestationPolicyResolve wraps every error path the resolver
// surfaces. SDK sentinels (types.ErrDuplicatePolicyName,
// attestation.ErrAttestationPolicyNotMet) remain reachable via
// errors.Is.
var ErrAttestationPolicyResolve = errors.New("verification/attestation_policy_resolver")

// Typed sentinels for the three resolution outcomes a caller
// needs to distinguish.
var (
	// ErrPolicyNotAdopted fires when entry.Header.AttestationPolicyName
	// is nil — the entry deliberately adopts NO multi-attester
	// policy and the primary signature alone authorises it.
	// Callers route this to "no policy gate; admit on primary-
	// signature verification alone."
	ErrPolicyNotAdopted = errors.New("entry adopts no AttestationPolicy")

	// ErrPolicyNameNotFound fires when entry.Header.AttestationPolicyName
	// references a name that is NOT in the schema's
	// AttestationPolicies slice. Means the entry was published
	// against a stale or unauthorised policy reference; admission
	// must reject (fail-closed).
	ErrPolicyNameNotFound = errors.New("AttestationPolicyName not declared on the entry's schema")

	// ErrNilSchemaParameters fires when the caller passes a nil
	// SchemaParameters. Programming error — only entries with a
	// resolved schema can be policy-checked.
	ErrNilSchemaParameters = errors.New("nil SchemaParameters (schema resolution required before policy lookup)")
)

// ResolveEntryAttestationPolicy follows the two-pointer chain
// from entry → schema → policy:
//
//	1. Read entry.Header.AttestationPolicyName.
//	   Nil   → return (nil, ErrPolicyNotAdopted) — caller's choice
//	          whether that's admissible (depends on whether the
//	          schema lists policies and whether one is required).
//	   "..." → continue.
//	2. Look up schemaParams.FindAttestationPolicy(*name).
//	   Hit   → return (&policy, nil).
//	   Miss  → return (nil, ErrPolicyNameNotFound).
//
// Returns ErrAttestationPolicyResolve wrapping the underlying
// sentinel; callers errors.Is on ErrPolicyNotAdopted /
// ErrPolicyNameNotFound to route granular HTTP rejection paths.
//
// IDEMPOTENT. Pure function of (entry header, schema params).
func ResolveEntryAttestationPolicy(
	entry *envelope.Entry,
	schemaParams *types.SchemaParameters,
) (*types.AttestationPolicy, error) {
	if entry == nil {
		return nil, fmt.Errorf("%w: nil entry", ErrAttestationPolicyResolve)
	}
	if schemaParams == nil {
		return nil, fmt.Errorf("%w: %w", ErrAttestationPolicyResolve, ErrNilSchemaParameters)
	}
	if entry.Header.AttestationPolicyName == nil {
		return nil, fmt.Errorf("%w: %w", ErrAttestationPolicyResolve, ErrPolicyNotAdopted)
	}
	name := *entry.Header.AttestationPolicyName
	if name == "" {
		// Empty-string is structurally different from nil but
		// semantically equivalent for routing.
		return nil, fmt.Errorf("%w: %w (empty AttestationPolicyName)",
			ErrAttestationPolicyResolve, ErrPolicyNotAdopted)
	}
	policy, ok := schemaParams.FindAttestationPolicy(name)
	if !ok {
		return nil, fmt.Errorf("%w: %w: %q",
			ErrAttestationPolicyResolve, ErrPolicyNameNotFound, name)
	}
	return &policy, nil
}

// VerifyEntryAttestationPolicyFromSchema is the JN-side end-to-
// end seam. Resolves the entry's policy via the schema, then
// invokes the SDK's attestation.VerifyEntryAttestationPolicy
// against the candidate attestation set.
//
// Returns:
//
//   - (nil, nil) if the entry adopts no policy (ErrPolicyNotAdopted).
//     The caller treats this as "no attestation gate" — primary-
//     signature verification alone is the authority.
//
//   - (report, nil) when the policy is satisfied (whether
//     Required or not).
//
//   - (report, attestation.ErrAttestationPolicyNotMet) when
//     policy.Required is true and the policy is not met. Hard
//     reject.
//
//   - (nil, err wrapping ErrAttestationPolicyResolve) for input-
//     guard rejections (nil entry / nil schema, missing policy
//     name on the schema, nil verifier, etc.). SDK sentinels
//     remain reachable via errors.Is.
//
// The primary's LogPosition is taken from primaryEntryPos; the
// caller materialises it from whatever source (Log_Time +
// canonical bytes provided by the upstream query).
func VerifyEntryAttestationPolicyFromSchema(
	ctx context.Context,
	primary types.EntryWithMetadata,
	schemaParams *types.SchemaParameters,
	candidates []types.EntryWithMetadata,
	sigVerifier attestation.SignatureVerifier,
	delegationResolver attestation.DelegationResolver,
	opts ...attestation.VerifyOption,
) (*attestation.PolicyReport, error) {
	if primary.CanonicalBytes == nil {
		return nil, fmt.Errorf("%w: primary EntryWithMetadata missing CanonicalBytes",
			ErrAttestationPolicyResolve)
	}
	// Deserialize once to read Header.AttestationPolicyName.
	entry, err := envelope.Deserialize(primary.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: deserialize primary: %w",
			ErrAttestationPolicyResolve, err)
	}
	policy, err := ResolveEntryAttestationPolicy(entry, schemaParams)
	if err != nil {
		if errors.Is(err, ErrPolicyNotAdopted) {
			// Entry deliberately adopted no policy; the policy
			// gate is a no-op for this entry. Caller's primary-
			// signature verification path is the only authority.
			return nil, nil
		}
		return nil, err
	}
	return attestation.VerifyEntryAttestationPolicy(
		ctx,
		primary,
		*policy,
		candidates,
		sigVerifier,
		delegationResolver,
		opts...,
	)
}

// Compile-time pin: v1.3.0 wire-field presence + helper signature.
// A future SDK rename or signature break in these symbols surfaces
// at the JN build time, not at runtime. Method expressions
// (Type.Method) are used so the pins do not deref a nil receiver
// at package init.
var (
	_ types.AttestationPolicy
	_ types.SchemaParameters
	_ = types.SchemaParameters.FindAttestationPolicy
	_ = types.SchemaParameters.ValidateAttestationPolicies
	_ = types.ErrDuplicatePolicyName
	_ = attestation.VerifyEntryAttestationPolicy
)
