/*
FILE PATH: api/verification/handlers/verify_complete.go

DESCRIPTION:

	GET /v1/verify/complete/{logID}/{pos} — read-side SDK Path C
	composite verification endpoint. Runs every opted-in verification
	stage in one frame (Signatures → Authority → Origin) on an
	already-on-log entry and returns a unified per-stage report.

	# SCOPE — NOT the ledger admission gate

	This handler is a READ-side verifier for external auditors that
	don't have a local SDK build. It runs on an entry that has
	ALREADY been committed to the ledger. Write-side admission
	(rejecting invalid submissions before commit) lives in the
	LEDGER process — JN does not gate writes. The two surfaces
	share the same SDK composite (verifier.VerifyComplete) but at
	different process boundaries and different cost models.

	The handler delegates to the JN seam verification.VerifyEntryViaSDK
	(added in PR C), which itself wraps the SDK's
	verifier.VerifyComplete. The JN seam owns sentinel wrapping;
	the SDK owns the cryptography.

	# STAGE OPT-INS

	This handler opts into the three position-anchored stages:

	  - Signatures (mandatory, runs first)
	  - Authority  (LeafReader + Fetcher + Extractor)
	  - Origin     (LeafReader + Fetcher)

	The Conditions and Cosignature stages require caller-supplied
	parameters (candidate-set, threshold, schema parameters) that
	don't make sense at a position-keyed read endpoint; callers
	needing those run the per-stage endpoints or call the JN seam
	directly.

	# RESPONSE SHAPE

	200 — { "all_green": bool, "report": <SDK *VerifyReport JSON> }
	400 — { "error": "invalid position" }     malformed sequence
	404 — { "error": "unknown log <id>" }     log not in LogQueries
	500 — { "error": "verify complete failed: <msg>" }
	         SDK envelope-level error (nil entry, nil verifier, etc.)

	Per-stage failures DO NOT return 500 — they return 200 with
	all_green=false and the per-stage Report populated. The SDK
	composite's discipline is that envelope-level errors are
	caller-fixable, per-stage failures are evidence to report.

	# REQUIRED Dependencies FIELDS

	  - SignatureVerifier — required. Without it the SDK rejects
	    with attestation.ErrNilSignatureVerifier and the handler
	    returns 500. Production deployments wire
	    did.DefaultVerifierRegistryWithRPC; tests inject a stub.
	  - LeafReader        — required.
	  - LogQueries[logID] — required (via fetcherFor).
	  - Extractor         — optional (Authority stage falls back to
	    schema-disabled condition classification).

KEY DEPENDENCIES:
  - verification.VerifyEntryViaSDK (PR C seam)
  - attesta verifier.VerifyComplete (SDK composite)
*/
package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"

	"github.com/clearcompass-ai/judicial-network/verification"
)

// PR-2 — read-time Stage 6 wiring.
//
// When deps.PolicyStageEnabled is true AND deps.PolicyStage carries
// an entry for the request's logID, this handler resolves the primary
// entry's adopted policy, fetches its candidates from the ledger's
// cosignature_of index, and threads the result through the SDK's
// VerifyComplete composite as PolicyParams.
//
// The Stage 6 path is best-effort: any failure preparing the stage
// (schema fetch, extractor, candidate hydration) is reported via the
// handler's standard error channel; per-stage policy outcomes (met /
// unmet, constraint violations) flow back to the caller inside the
// SDK's VerifyReport.Policy field.
//
// The handler's three-stage behavior (Signatures + Authority + Origin)
// is unchanged when the flag is off or no PolicyStageDeps are wired.

// VerifyCompleteHandler handles GET /v1/verify/complete/{logID}/{pos}.
//
// Pulls the entry at the position, builds the SDK Path C composite
// params, and delegates to verification.VerifyEntryViaSDK.
type VerifyCompleteHandler struct{ deps *Dependencies }

func NewVerifyCompleteHandler(deps *Dependencies) *VerifyCompleteHandler {
	return &VerifyCompleteHandler{deps: deps}
}

func (h *VerifyCompleteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logID := r.PathValue("logID")
	posStr := r.PathValue("pos")

	pos, err := strconv.ParseUint(posStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid position")
		return
	}

	fetcher, err := h.deps.fetcherFor(logID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	logPos := types.LogPosition{LogDID: logID, Sequence: pos}
	leafKey := smt.DeriveKey(logPos)

	meta, err := fetcher.Fetch(ctx, logPos)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("fetch entry: %v", err))
		return
	}
	entry, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			fmt.Sprintf("deserialize entry: %v", err))
		return
	}

	params := verifier.VerifyCompleteParams{
		Entry:             entry,
		SignatureVerifier: h.deps.SignatureVerifier,
		AuthorityParams: &verifier.AuthorityStageParams{
			LeafKey:    leafKey,
			LeafReader: h.deps.LeafReader,
			Fetcher:    fetcher,
			Extractor:  h.deps.Extractor,
		},
		OriginParams: &verifier.OriginStageParams{
			LeafKey:    leafKey,
			LeafReader: h.deps.LeafReader,
			Fetcher:    fetcher,
		},
	}

	// PR-2 — Policy stage (read-time Stage 6). Gated by feature flag
	// + per-log injection (see deps.PolicyStage commentary). Both
	// axes must be present; either-off keeps the handler's three-
	// stage shape from PR D.
	if h.deps.PolicyStageEnabled {
		if psDeps, ok := h.deps.PolicyStage[logID]; ok {
			policyParams, perr := buildPolicyStageParams(
				ctx, entry, meta, psDeps, h.deps.Extractor,
			)
			if perr != nil {
				writeError(w, http.StatusInternalServerError,
					fmt.Sprintf("policy stage prep failed: %v", perr))
				return
			}
			// policyParams is nil when the primary adopts no policy
			// or has no SchemaRef — both are valid "skip Stage 6"
			// outcomes and leave params.PolicyParams unset, which
			// the SDK composite treats as Stage 6 not requested.
			if policyParams != nil {
				params.PolicyParams = policyParams
			}
		}
	}

	result, err := verification.VerifyEntryViaSDK(ctx, params)
	if err != nil {
		// Envelope-level rejection from the SDK — caller-fixable
		// (nil verifier wiring, malformed envelope). Surface the
		// JN sentinel chain so operators see exactly which guard
		// fired.
		status := http.StatusInternalServerError
		if errors.Is(err, verification.ErrPathCSDK) {
			status = http.StatusInternalServerError
		}
		writeError(w, status, fmt.Sprintf("verify complete failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"all_green": result.AllGreen,
		"report":    result.Report,
	})
}

// buildPolicyStageParams is a small handler-local helper that
// composes verification.ResolveSchemaParametersForEntry with
// verification.BuildPolicyStageParams. Kept here (rather than in the
// verification package) so the handler owns the schema-resolution
// step — verification/ is the SDK seam and stays free of HTTP-handler
// orchestration details.
func buildPolicyStageParams(
	ctx context.Context,
	entry *envelope.Entry,
	primary *types.EntryWithMetadata,
	deps PolicyStageDeps,
	extractor schemaParameterExtractor,
) (*verifier.PolicyStageParams, error) {
	// Resolve the primary's schema parameters (including
	// AttestationPolicies). nil-params is a clean skip: the entry
	// has no schema (Path A) and therefore no policy to evaluate.
	schemaParams, err := verification.ResolveSchemaParametersForEntry(
		ctx, entry, deps.Fetcher, extractor,
	)
	if err != nil {
		return nil, err
	}
	if schemaParams == nil {
		return nil, nil
	}
	return verification.BuildPolicyStageParams(
		ctx, *primary, schemaParams, deps.Query, deps.Fetcher, deps.DelegationResolver,
	)
}

// schemaParameterExtractor is the local alias for the SDK's
// schema.SchemaParameterExtractor. Aliasing here keeps
// buildPolicyStageParams's signature short without dragging another
// SDK import into the handler file (the alias is consumed only here).
type schemaParameterExtractor interface {
	Extract(*envelope.Entry) (*types.SchemaParameters, error)
}
