package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// VerifyBatchHandler handles GET /v1/verify/batch/{logID}/{positions}.
// Positions is a comma-separated list of uint64.
type VerifyBatchHandler struct{ deps *Dependencies }

func NewVerifyBatchHandler(deps *Dependencies) *VerifyBatchHandler {
	return &VerifyBatchHandler{deps: deps}
}

type batchItem struct {
	Position  uint64                      `json:"position"`
	Origin    *verifier.OriginEvaluation  `json:"origin,omitempty"`
	Authority *verifier.AuthorityEvaluation `json:"authority,omitempty"`
	Error     string                      `json:"error,omitempty"`
}

func (h *VerifyBatchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logID := r.PathValue("logID")
	positionsStr := r.PathValue("positions")

	fetcher, err := h.deps.fetcherFor(logID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	parts := strings.Split(positionsStr, ",")
	results := make([]batchItem, 0, len(parts))

	for _, p := range parts {
		pos, err := strconv.ParseUint(strings.TrimSpace(p), 10, 64)
		if err != nil {
			results = append(results, batchItem{Error: "invalid position: " + p})
			continue
		}

		item := batchItem{Position: pos}
		leafKey := smt.DeriveKey(types.LogPosition{LogDID: logID, Sequence: pos})

		origin, err := verifier.EvaluateOrigin(leafKey, h.deps.LeafReader, fetcher)
		if err != nil {
			item.Error = err.Error()
		} else {
			item.Origin = origin
		}

		auth, err := verifier.EvaluateAuthority(
			leafKey, h.deps.LeafReader, fetcher, h.deps.Extractor,
		)
		if err == nil {
			item.Authority = auth
		}

		results = append(results, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}
