package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
	"github.com/clearcompass-ai/judicial-network/topology"
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

	// v0.3.0: one lookup yields the source log's full witness topology
	// (keys + K + NetworkID + BLS verifier) — replacing the three
	// parallel maps and eliminating the class of bug where K and keys
	// drift out of sync for the same log DID.
	set, ok := h.deps.WitnessSets[req.SourceLogDID]
	if !ok || set == nil {
		writeError(w, http.StatusBadRequest, "no witness set for source log")
		return
	}

	err := verifier.VerifyCrossLogProof(req.Proof, set, topology.ExtractAnchorPayload)
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
