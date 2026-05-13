/*
FILE PATH: api/verification/handlers/verify_complete.go

DESCRIPTION:

	GET /v1/verify/complete/{logID}/{pos} — the SDK Path C composite
	admission gate. Runs every opted-in verification stage in one
	frame (Signatures → Authority → Origin) and returns a unified
	per-stage report.

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
	don't make sense at the boot-time admission gate; callers needing
	those run the per-stage endpoints (/v1/verify/cosignature in
	future, or call the JN seam directly).

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
