package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/schema"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// Dependencies shared across all verification handlers.
// Uses real SDK interfaces — no invented abstractions.
//
// v0.3.0 (Phase 3 of the upgrade): WitnessSets replaces the legacy
// trio of WitnessKeys / WitnessQuorum / WitnessNetwork. SDK Principle
// 10 (Two-Tier Quorum Encapsulation): keys + K + NetworkID + BLS
// verifier are bound together at construction time inside one
// *cosign.WitnessKeySet — eliminating the class of bug where the
// three parallel maps drift out of sync for the same log DID.
type Dependencies struct {
	LogQueries     map[string]sdklog.LedgerQueryAPI
	LeafReader     smt.LeafReader
	Extractor      schema.SchemaParameterExtractor
	SchemaResolver builder.SchemaResolver

	// WitnessSets is the source of truth for per-log witness topology.
	// One entry per log DID; the *cosign.WitnessKeySet inside carries
	// keys, K, NetworkID, and the BLSAggregateVerifier together.
	// Constructor failure (zero NetworkID, duplicate IDs, K outside
	// [1, len(keys)]) is caught at boot, not at HTTP-request time.
	WitnessSets map[string]*cosign.WitnessKeySet

	// SignatureVerifier resolves DID method → SignatureVerifier for
	// the Path C admission gate (/v1/verify/complete). Production:
	// did.DefaultVerifierRegistryWithRPC bound to the exchange's
	// destination DID with judicial vendor mappings layered on top.
	// Per-handler responsibility — only VerifyCompleteHandler reads
	// this field. Empty (nil) keeps boot clean for deployments that
	// don't expose /v1/verify/complete.
	SignatureVerifier attestation.SignatureVerifier
}

// resolveLog finds the ledger query API for a given log identifier.
func (d *Dependencies) resolveLog(logID string) (sdklog.LedgerQueryAPI, bool) {
	q, ok := d.LogQueries[logID]
	return q, ok
}

// fetcherFor creates an EntryFetcher adapter for a specific log.
func (d *Dependencies) fetcherFor(logID string) (types.EntryFetcher, error) {
	query, ok := d.resolveLog(logID)
	if !ok {
		return nil, fmt.Errorf("unknown log %s", logID)
	}
	return &ledgerFetcher{query: query, logDID: logID}, nil
}

// ledgerFetcher adapts LedgerQueryAPI to types.EntryFetcher.
// v0.3.0: Fetch now takes ctx so the underlying ScanFromPosition RPC
// honours the caller's request deadline.
type ledgerFetcher struct {
	query  sdklog.LedgerQueryAPI
	logDID string
}

func (f *ledgerFetcher) Fetch(ctx context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error) {
	entries, err := f.query.ScanFromPosition(ctx, pos.Sequence, 1)
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

	leafKey := smt.DeriveKey(types.LogPosition{LogDID: logID, Sequence: pos})

	result, err := verifier.EvaluateOrigin(ctx, leafKey, h.deps.LeafReader, fetcher)
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
