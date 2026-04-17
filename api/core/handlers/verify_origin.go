package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// Dependencies shared across all verification handlers.
// Uses real SDK interfaces — no invented abstractions.
type Dependencies struct {
	LogQueries     map[string]sdklog.OperatorQueryAPI
	LeafReader     smt.LeafReader
	Extractor      schema.SchemaParameterExtractor
	SchemaResolver builder.SchemaResolver
	BLSVerifier    signatures.BLSVerifier
	WitnessKeys    map[string][]types.WitnessPublicKey // logDID → keys
	WitnessQuorum  map[string]int                      // logDID → K
}

// resolveLog finds the operator query API for a given log identifier.
func (d *Dependencies) resolveLog(logID string) (sdklog.OperatorQueryAPI, bool) {
	q, ok := d.LogQueries[logID]
	return q, ok
}

// fetcherFor creates an EntryFetcher adapter for a specific log.
func (d *Dependencies) fetcherFor(logID string) (verifier.EntryFetcher, error) {
	query, ok := d.resolveLog(logID)
	if !ok {
		return nil, fmt.Errorf("unknown log %s", logID)
	}
	return &operatorFetcher{query: query, logDID: logID}, nil
}

// operatorFetcher adapts OperatorQueryAPI to verifier.EntryFetcher.
type operatorFetcher struct {
	query  sdklog.OperatorQueryAPI
	logDID string
}

func (f *operatorFetcher) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	entries, err := f.query.ScanFromPosition(pos.Sequence, 1)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("entry not found at %s", pos)
	}
	return &entries[0], nil
}

// VerifyOriginHandler handles GET /v1/verify/origin/{logID}/{pos}.
type VerifyOriginHandler struct{ deps *Dependencies }

func NewVerifyOriginHandler(deps *Dependencies) *VerifyOriginHandler {
	return &VerifyOriginHandler{deps: deps}
}

func (h *VerifyOriginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	result, err := verifier.EvaluateOrigin(leafKey, h.deps.LeafReader, fetcher)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "origin evaluation failed")
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// ─── Shared helpers ─────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
