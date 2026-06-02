/*
FILE PATH: api/verification/handlers/verify_cosignature.go

GET /v1/verify/cosignature/{logID}/{pos} — read-side CRYPTO-AWARE cosignature-mix
verification. The auditor/read-side dual of the exchange submit gate
(api/exchange/handlers/submit_gate.go).

# WHY THIS EXISTS

The submit gate runs verification.CheckCosignature PRE-admission: it enforces the
JN-domain role/exchange/threshold mix but does NOT verify the signatures
cryptographically — it trusts the ledger to do that at admission. That is correct
for the write path (the ledger is the crypto authority downstream), but it leaves
the dual-verification loop open: nothing INDEPENDENTLY confirms, on read, that an
admitted entry's cosignature mix is BOTH cryptographically valid AND
policy-compliant.

This endpoint closes it. On an ALREADY-committed entry it runs
verification.CheckCosignatureWithVerifier, which runs
attestation.VerifyEntrySignatures FIRST (every signature crypto-verified against
its declared SignerDID) and only then applies the same role/exchange/threshold
mix the gate uses. An external auditor calling this trusts neither the ledger nor
the exchange — it re-derives both halves from the entry alone.

# BUNDLE RESOLUTION

The cosignature policy + exchange DID are per-jurisdiction, keyed by the entry's
own Header.Destination — so they resolve at a position-keyed endpoint exactly as
the submit gate resolves them from the destination DID. The RoleResolver is the
per-entry PayloadRoleResolver derived from the entry's signed_by_capacities (the
"no off-log registry" model).

# RESPONSE

	200 — { "ok": bool, "event_type", "rejection", "reason" }
	      (ok=false carries the closed-set rejection token + reason)
	400 — invalid position / malformed signed_by_capacities
	404 — unknown log, or the entry's destination is not a registered exchange
	500 — SDK envelope-level crypto error (nil entry/verifier, empty sigs,
	      primary-DID mismatch) — surfaced via verification.ErrCosignatureCryptoSDK
	503 — SignatureVerifier or Registry not wired

KEY DEPENDENCIES:
  - verification.CheckCosignatureWithVerifier (crypto + JN role/threshold mix)
  - verification.NewPayloadRoleResolver       (per-entry role lookup)
  - jurisdiction.Registry / Bundle            (policy + exchange DID)
*/
package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/verification"
)

// VerifyCosignatureHandler handles GET /v1/verify/cosignature/{logID}/{pos}.
type VerifyCosignatureHandler struct{ deps *Dependencies }

func NewVerifyCosignatureHandler(deps *Dependencies) *VerifyCosignatureHandler {
	return &VerifyCosignatureHandler{deps: deps}
}

func (h *VerifyCosignatureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logID := r.PathValue("logID")
	posStr := r.PathValue("pos")

	if h.deps.SignatureVerifier == nil || h.deps.Registry == nil {
		writeError(w, http.StatusServiceUnavailable,
			"cosignature verification requires a wired SignatureVerifier + jurisdiction Registry")
		return
	}

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
	meta, err := fetcher.Fetch(ctx, types.LogPosition{LogDID: logID, Sequence: pos})
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("fetch entry: %v", err))
		return
	}
	entry, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("deserialize entry: %v", err))
		return
	}

	// Resolve the destination bundle exactly as the submit gate does — the
	// cosignature policy + exchange DID are keyed by the entry's own Destination.
	bundle, err := h.deps.Registry.Bundle(entry.Header.Destination)
	if err != nil {
		writeError(w, http.StatusNotFound,
			fmt.Sprintf("unknown exchange %q: %v", entry.Header.Destination, err))
		return
	}

	// Per-entry role resolver from the entry's own signed_by_capacities.
	resolver, err := verification.NewPayloadRoleResolver(entry.DomainPayload)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("malformed signed_by_capacities: %v", err))
		return
	}

	verdict, err := verification.CheckCosignatureWithVerifier(
		ctx, entry, bundle.CosignaturePolicy(), resolver, bundle.ExchangeDID(), h.deps.SignatureVerifier,
	)
	if err != nil {
		// Envelope-level crypto rejection (nil entry/verifier, empty sigs,
		// primary-DID mismatch) — caller-fixable; surface the JN sentinel chain.
		status := http.StatusInternalServerError
		if errors.Is(err, verification.ErrCosignatureCryptoSDK) {
			status = http.StatusInternalServerError
		}
		writeError(w, status, fmt.Sprintf("cosignature verify failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         verdict.OK,
		"event_type": verdict.EventType,
		"rejection":  string(verdict.Rejection),
		"reason":     verdict.Reason,
	})
}
