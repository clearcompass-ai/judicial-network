package handlers

import (
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"

	"github.com/clearcompass-ai/judicial-network/verification/trust"
)

// VerifyAuthorityHandler handles GET /v1/verify/authority/{logID}/{pos}.
type VerifyAuthorityHandler struct{ deps *Dependencies }

func NewVerifyAuthorityHandler(deps *Dependencies) *VerifyAuthorityHandler {
	return &VerifyAuthorityHandler{deps: deps}
}

func (h *VerifyAuthorityHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	entity := types.LogPosition{LogDID: logID, Sequence: pos}

	// v1.34 migration: legacy verifier.EvaluateAuthority is deprecated.
	// Migrated to verifier.EvaluateAuthorityWithTrust via a LocalTrust
	// adapter — same (fetcher, leafReader) inputs, parity locked by
	// trust.TestLocalTrust_LegacyParity_EvaluateAuthority.
	result, err := verifier.EvaluateAuthorityWithTrust(
		ctx, entity,
		trust.NewLocalTrust(fetcher, h.deps.LeafReader),
		h.deps.Extractor, verifier.AsOf{})

	if err != nil {
		writeError(w, http.StatusInternalServerError, "authority evaluation failed")
		return
	}

	writeJSON(w, http.StatusOK, result)
}
