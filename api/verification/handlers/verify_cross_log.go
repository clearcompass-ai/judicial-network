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

	// Look up witness keys for the source log.
	keys, ok := h.deps.WitnessKeys[req.SourceLogDID]
	if !ok {
		writeError(w, http.StatusBadRequest, "no witness keys for source log")
		return
	}
	quorum := h.deps.WitnessQuorum[req.SourceLogDID]
	networkID := h.deps.WitnessNetwork[req.SourceLogDID]
	if networkID.IsZero() {
		writeError(w, http.StatusBadRequest, "no network ID for source log")
		return
	}

	err := verifier.VerifyCrossLogProof(req.Proof, keys, quorum, networkID,
		h.deps.BLSVerifier, topology.ExtractAnchorPayload)
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
