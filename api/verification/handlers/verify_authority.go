package handlers

import (
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// VerifyAuthorityHandler handles GET /v1/verify/authority/{logID}/{pos}.
type VerifyAuthorityHandler struct{ deps *Dependencies }

func NewVerifyAuthorityHandler(deps *Dependencies) *VerifyAuthorityHandler {
	return &VerifyAuthorityHandler{deps: deps}
}

func (h *VerifyAuthorityHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	leafKey := smt.DeriveKey(types.LogPosition{LogDID: logID, Sequence: pos})

	result, err := verifier.EvaluateAuthority(
		leafKey, h.deps.LeafReader, fetcher, h.deps.Extractor,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authority evaluation failed")
		return
	}

	writeJSON(w, http.StatusOK, result)
}
