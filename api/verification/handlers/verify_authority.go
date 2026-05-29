package handlers

import (
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
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

	// Migrated v1.35.0: EvaluateAuthority → EvaluateAuthorityWithTrust over
	// SingleLog at asOf=latest. Byte-identical behavior.
	result, err := verifier.EvaluateAuthorityWithTrust(ctx,
		types.LogPosition{LogDID: logID, Sequence: pos},
		verifier.SingleLog{Fetcher: fetcher, LeafReader: h.deps.LeafReader},
		h.deps.Extractor, verifier.AsOf{})

	if err != nil {
		writeError(w, http.StatusInternalServerError, "authority evaluation failed")
		return
	}

	writeJSON(w, http.StatusOK, result)
}
