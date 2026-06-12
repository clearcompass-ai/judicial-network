package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/types"

	"github.com/clearcompass-ai/judicial-network/verification/trust"

	"github.com/clearcompass-ai/judicial-network/verification/eras"
)

// VerifyCrossLogHandler handles POST /v1/verify/cross-log.
type VerifyCrossLogHandler struct{ deps *Dependencies }

func NewVerifyCrossLogHandler(deps *Dependencies) *VerifyCrossLogHandler {
	return &VerifyCrossLogHandler{deps: deps}
}

func (h *VerifyCrossLogHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Proof        types.CrossLogProof `json:"proof"`
		SourceLogDID string              `json:"source_log_did"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// FED-1 #107: resolve the source log's witness set ERA-CORRECTLY for
	// THIS proof's cosigned head — the set that actually cosigned it, from
	// the genesis-rooted journaled rotation chain. The taxonomy is never
	// folded: an unknown log is a config-class 400; a warming journal is a
	// retryable 503 (startup, not staleness); a head no chain set explains
	// is a named 422 (re-prove against a live head, or the chain is bad).
	if h.deps.Eras == nil {
		writeError(w, http.StatusInternalServerError, "era resolution not configured")
		return
	}
	set, eraErr := h.deps.Eras.SetForHead(r.Context(), req.SourceLogDID, req.Proof.SourceTreeHead)
	if eraErr != nil {
		switch {
		case errors.Is(eraErr, eras.ErrNoSuchPeer):
			writeError(w, http.StatusBadRequest, "no trust root configured for source log")
		case errors.Is(eraErr, eras.ErrWarming):
			w.Header().Set("Retry-After", "5")
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": "rotation journal warming up for source log — retry",
				"class": "warming",
			})
		default: // eras.ErrCannotResolveEra
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"error": eraErr.Error(),
				"class": "cannot_resolve_era",
			})
		}
		return
	}

	// SDK-4: gate on the source log's pinned burn status from the journal.
	ts := trust.StatusFor(r.Context(), h.deps.Journal, req.SourceLogDID)
	err := anchor.VerifyCrossLog(req.Proof, set, ts)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid":             true,
		"source_entry":      req.Proof.SourceEntry,
		"source_entry_hash": req.Proof.SourceEntryHash,
	})
}
