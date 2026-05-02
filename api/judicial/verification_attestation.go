/*
FILE PATH: api/judicial/verification_attestation.go

DESCRIPTION:
    Read-side identity / background verification handlers.

      GET /v1/judicial/verification/background-check?party_did=...
                                                → BackgroundCheck
      GET /v1/judicial/verification/key-attestation?entity_did=...&log_did=...&seq=...
                                                → 501 (needs AttestationFinder
                                                  + TrustedExchangeChecker)

    Daily reality:
      - Background check: when an attorney files an appearance, the
        court runs a background check on the represented party's DID
        across the cases log. Sealed cases are flagged but their
        details withheld.
      - Key attestation: confirms an officer's key has at least one
        valid attestation from a trusted exchange. Stub until the
        composer wires the AttestationFinder + TrustedExchangeChecker
        deps in C6.
*/
package judicial

import (
	"net/http"

	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/verification"
)

// ─────────────────────────────────────────────────────────────────────
// GET /v1/judicial/verification/background-check?party_did=...
// ─────────────────────────────────────────────────────────────────────

type verifyBackgroundCheckHandler struct{ deps *Dependencies }

func (h *verifyBackgroundCheckHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	q := r.URL.Query()
	partyDID := q.Get("party_did")
	if partyDID == "" {
		writeError(w, http.StatusBadRequest, "party_did required")
		return
	}
	logDID := r.Header.Get("X-Cases-Log-DID")
	if logDID == "" {
		writeError(w, http.StatusBadRequest, "X-Cases-Log-DID header required")
		return
	}
	api, ok := h.deps.LogQueries[logDID]
	if !ok {
		writeError(w, http.StatusInternalServerError, "no LogQueries entry for "+logDID)
		return
	}
	assoc, err := verification.BackgroundCheck(partyDID, backgroundQuerierAdapter{api: api}, h.deps.LeafReader)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, assoc)
}

type backgroundQuerierAdapter struct{ api sdklog.OperatorQueryAPI }

func (a backgroundQuerierAdapter) QueryBySignerDID(did string) ([]types.EntryWithMetadata, error) {
	return a.api.QueryBySignerDID(did)
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/judicial/verification/key-attestation
// ─────────────────────────────────────────────────────────────────────

// VerifyKeyAttestation needs an AttestationFinder + TrustedExchangeChecker
// — neither is on Dependencies today. Stubbed until C6 wires the
// trust-set registry.
type verifyKeyAttestationHandler struct{ deps *Dependencies }

func (h *verifyKeyAttestationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"key attestation requires AttestationFinder + TrustedExchangeChecker; wired in C6")
}
