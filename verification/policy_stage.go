/*
FILE PATH: verification/policy_stage.go

DESCRIPTION:

	Read-time Stage 6 orchestrator for JN. Gathers the four inputs
	the SDK's verifier.PolicyStageParams requires from the ledger
	HTTP surface and packages them ready for the SDK's
	VerifyComplete composite or for a direct
	attestation.VerifyEntryAttestationPolicy call:

	  1. Primary           — caller-supplied (already on log)
	  2. Policy            — resolved via schemaParams.FindAttestationPolicy
	  3. Candidates        — sdklog.LedgerQueryAPI.QueryByCosignatureOf
	                         hydrated via types.EntryFetcher
	  4. DelegationResolver — caller-supplied (typically
	                          *LedgerDelegationResolver from this package)

	# SCOPE — read-time only

	This file does NOT enforce the policy at write time — the ledger's
	admission gate (PR-I + LedgerPolicyResolver) handles admission-
	enforced policies. For async policies (AdmissionEnforced=false,
	the JN default), this runner is the place where the threshold is
	evaluated against newly-arrived cosignatures.

	The runner returns (nil, nil) when the entry adopts no policy —
	the caller treats that as "no Stage 6 to run."

	# WHY NOT RE-USE VerifyEntryAttestationPolicyFromSchema

	verification/attestation_policy_resolver.go already exposes the
	end-to-end seam in one call. This file is one layer lower: it
	prepares the SDK PolicyStageParams struct so callers driving
	the SDK's VerifyComplete composite (api/verification/handlers/
	verify_complete.go in PR-2) can hand the params to the composite
	verifier in a single frame. The seam stays useful for callers
	that want the verdict directly without driving VerifyComplete.

KEY DEPENDENCIES:
  - attesta v1.5.1 verifier.PolicyStageParams (target shape)
  - attesta v1.5.1 attestation.Policy, DelegationResolver
  - attesta v1.5.1 sdklog.LedgerQueryAPI (cosignature_of)
  - attesta v1.5.1 core/envelope.Deserialize (read policy name)
  - attesta v1.5.1 types.SchemaParameters.FindAttestationPolicy
*/
package verification

import (
	"context"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/schema"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// ErrPolicyStage is the umbrella sentinel for every error this
// orchestrator surfaces. Callers errors.Is(err, ErrPolicyStage) to
// distinguish "stage prep failed (caller-fixable)" from policy
// evaluation outcomes (which arrive on the verdict, not the error).
var ErrPolicyStage = errors.New("verification/policy_stage")

// BuildPolicyStageParams gathers the SDK verifier.PolicyStageParams
// inputs for primary's adopted policy, fetching candidates from the
// ledger's cosignature_of index and hydrating their canonical bytes.
//
// Returns (nil, nil) when primary adopts no policy (the SDK seam
// short-circuit, see ResolveEntryAttestationPolicy in
// attestation_policy_resolver.go). Returns (nil, err) wrapping
// ErrPolicyStage on any prep failure; the caller should NOT
// proceed to invoke Stage 6 in that case.
//
// On success, callers feed the returned *PolicyStageParams into
// verifier.VerifyCompleteParams.PolicyParams (composite Path C) or
// invoke attestation.VerifyEntryAttestationPolicy directly with the
// four fields.
//
// IDEMPOTENT. Pure function of the inputs (the ledger queries are
// read-only from JN's perspective).
func BuildPolicyStageParams(
	ctx context.Context,
	primary types.EntryWithMetadata,
	schemaParams *types.SchemaParameters,
	query sdklog.LedgerQueryAPI,
	fetcher types.EntryFetcher,
	delegationResolver attestation.DelegationResolver,
) (*verifier.PolicyStageParams, error) {
	if primary.CanonicalBytes == nil {
		return nil, fmt.Errorf("%w: primary CanonicalBytes required", ErrPolicyStage)
	}
	if schemaParams == nil {
		return nil, fmt.Errorf("%w: %w", ErrPolicyStage, ErrNilSchemaParameters)
	}
	if query == nil {
		return nil, fmt.Errorf("%w: LedgerQueryAPI required", ErrPolicyStage)
	}
	if fetcher == nil {
		return nil, fmt.Errorf("%w: EntryFetcher required", ErrPolicyStage)
	}

	// 1. Deserialize primary so we can read Header.AttestationPolicyName.
	entry, err := envelope.Deserialize(primary.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: deserialize primary: %w", ErrPolicyStage, err)
	}

	// 2. Resolve the entry's adopted policy via the SDK seam in
	// attestation_policy_resolver.go (single source of truth for
	// the nil-policy short-circuit + error routing).
	policy, err := ResolveEntryAttestationPolicy(entry, schemaParams)
	if err != nil {
		if errors.Is(err, ErrPolicyNotAdopted) {
			// Entry adopts no policy. Caller skips Stage 6.
			return nil, nil
		}
		return nil, err
	}

	// 3. Query candidates from the ledger's cosignature_of index.
	// Returned EntryWithMetadata has CanonicalBytes==nil per the
	// ledger's egress mandate — we hydrate each one via the
	// supplied fetcher.
	candidates, err := query.QueryByCosignatureOf(ctx, primary.Position)
	if err != nil {
		return nil, fmt.Errorf("%w: cosignature_of(%s): %w",
			ErrPolicyStage, primary.Position, err)
	}

	// 4. Hydrate every candidate. A missing candidate (race: indexed
	// but not yet committed to byte store) is skipped, not fatal —
	// admission has already accepted them; the absence is transient.
	hydrated := make([]types.EntryWithMetadata, 0, len(candidates))
	for _, c := range candidates {
		if c.CanonicalBytes != nil {
			hydrated = append(hydrated, c)
			continue
		}
		full, ferr := fetcher.Fetch(ctx, c.Position)
		if ferr != nil {
			return nil, fmt.Errorf("%w: hydrate candidate %s: %w",
				ErrPolicyStage, c.Position, ferr)
		}
		if full == nil || full.CanonicalBytes == nil {
			continue
		}
		hydrated = append(hydrated, *full)
	}

	return &verifier.PolicyStageParams{
		Primary:            primary,
		Policy:             *policy,
		Candidates:         hydrated,
		DelegationResolver: delegationResolver,
	}, nil
}

// ResolveSchemaParametersForEntry fetches the schema entry referenced
// by the primary's Header.SchemaRef and runs the supplied Extractor
// to produce the full SchemaParameters (including AttestationPolicies,
// which BuildPolicyStageParams needs).
//
// Returns (nil, nil) when primary has no SchemaRef (Path A entries,
// e.g. commentary, never adopt a policy and have nothing to look up).
// Returns (nil, err wrapping ErrPolicyStage) for any fetch/decode
// failure.
//
// Separate from BuildPolicyStageParams so test fixtures can pre-build
// SchemaParameters directly without round-tripping through the
// fetcher.
func ResolveSchemaParametersForEntry(
	ctx context.Context,
	primary *envelope.Entry,
	fetcher types.EntryFetcher,
	extractor schema.SchemaParameterExtractor,
) (*types.SchemaParameters, error) {
	if primary == nil {
		return nil, fmt.Errorf("%w: nil primary entry", ErrPolicyStage)
	}
	if primary.Header.SchemaRef == nil {
		return nil, nil // Path A entry; no schema to resolve.
	}
	if fetcher == nil {
		return nil, fmt.Errorf("%w: EntryFetcher required", ErrPolicyStage)
	}
	if extractor == nil {
		return nil, fmt.Errorf("%w: SchemaParameterExtractor required", ErrPolicyStage)
	}
	ref := *primary.Header.SchemaRef
	schemaEWM, err := fetcher.Fetch(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch schema %s: %w", ErrPolicyStage, ref, err)
	}
	if schemaEWM == nil || schemaEWM.CanonicalBytes == nil {
		return nil, fmt.Errorf("%w: schema entry %s not found", ErrPolicyStage, ref)
	}
	schemaEntry, err := envelope.Deserialize(schemaEWM.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: deserialize schema %s: %w", ErrPolicyStage, ref, err)
	}
	params, err := extractor.Extract(schemaEntry)
	if err != nil {
		return nil, fmt.Errorf("%w: extract schema params %s: %w", ErrPolicyStage, ref, err)
	}
	return params, nil
}
