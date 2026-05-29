package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"

	"github.com/clearcompass-ai/judicial-network/verification/trust"
)

// VerifyBatchHandler handles GET /v1/verify/batch/{logID}/{positions}.
// Positions is a comma-separated list of uint64.
type VerifyBatchHandler struct{ deps *Dependencies }

func NewVerifyBatchHandler(deps *Dependencies) *VerifyBatchHandler {
	return &VerifyBatchHandler{deps: deps}
}

type batchItem struct {
	Position  uint64                        `json:"position"`
	Origin    *verifier.OriginEvaluation    `json:"origin,omitempty"`
	Authority *verifier.AuthorityEvaluation `json:"authority,omitempty"`
	Error     string                        `json:"error,omitempty"`
}

func (h *VerifyBatchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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
		entity := types.LogPosition{LogDID: logID, Sequence: pos}
		leafKey := smt.DeriveKey(entity)

		// EvaluateOrigin has no WithTrust variant in attesta v1.34;
		// stays on the legacy single-reader API until the SDK ships
		// EvaluateOriginWithTrust (tracked separately).
		origin, err := verifier.EvaluateOrigin(ctx, leafKey, h.deps.LeafReader, fetcher)
		if err != nil {
			item.Error = err.Error()
		} else {
			item.Origin = origin
		}

		// v1.34 migration: legacy verifier.EvaluateAuthority is deprecated.
		// Migrated to verifier.EvaluateAuthorityWithTrust via a LocalTrust
		// adapter — parity locked by
		// trust.TestLocalTrust_LegacyParity_EvaluateAuthority.
		auth, err := verifier.EvaluateAuthorityWithTrust(
			ctx, entity,
			trust.NewLocalTrust(fetcher, h.deps.LeafReader),
			h.deps.Extractor, verifier.AsOf{})

		if err == nil {
			item.Authority = auth
		}

		results = append(results, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}
