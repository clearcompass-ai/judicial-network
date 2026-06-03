package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

// VerifyBatchHandler handles GET /v1/verify/batch/{logID}/{positions}.
// Positions is a comma-separated list of uint64.
//
// C-4 of PR-C: shares the verify_authority.go ?as_of= parameter
// semantics — the same pinned head is applied to every position in
// the batch. Mixing as-of policies within one batch would defeat
// the determinism guarantee (Goal 6); a caller wanting per-position
// asOfs issues parallel verify/authority calls.
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

	trustProv := h.deps.PickTrust(fetcher)

	// ZT-IMM-01: one pinned head for the whole batch (shared as-of) —
	// resolved, never an implicit wall-clock latest.
	asOf, err := resolveAsOf(ctx, r, logID, trustProv, h.deps.Journal)
	if err != nil {
		writeError(w, asOfErrorStatus(err), err.Error())
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

		// EvaluateOrigin has no WithTrust variant in baseproof v1.34;
		// stays on the legacy single-reader API until the SDK ships
		// EvaluateOriginWithTrust (tracked separately).
		origin, err := verifier.EvaluateOrigin(ctx, leafKey, h.deps.LeafReader, fetcher)
		if err != nil {
			item.Error = err.Error()
		} else {
			item.Origin = origin
		}

		auth, err := verifier.EvaluateAuthorityWithTrust(
			ctx, entity, trustProv, h.deps.Extractor, asOf)

		if err == nil {
			item.Authority = auth
		}

		results = append(results, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}
