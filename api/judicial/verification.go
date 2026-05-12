/*
FILE PATH: api/judicial/verification.go

DESCRIPTION:

	Read-side verification handlers — daily clerk / counsel / appellate
	activities checking the on-log state.

	  GET  /v1/judicial/verification/case-status         → GetCaseStatus
	  GET  /v1/judicial/verification/enforcement-status  → CheckEnforcementStatus
	  POST /v1/judicial/verification/filing-delegation   → VerifyFilingDelegation
	  GET  /v1/judicial/verification/custody-chain       → ReconstructCustodyChain

	Read-only — no auth context required, but auth IS enforced (no
	anonymous reads on a court log).
*/
package judicial

import (
	"context"
	"net/http"

	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/verification"
)

func registerVerificationRoutes(mux *http.ServeMux, deps *Dependencies) {
	mux.Handle("GET /v1/judicial/verification/case-status", &verifyCaseStatusHandler{deps: deps})
	mux.Handle("GET /v1/judicial/verification/enforcement-status", &verifyEnforcementHandler{deps: deps})
	mux.Handle("POST /v1/judicial/verification/filing-delegation", &verifyFilingDelegationHandler{deps: deps})
	mux.Handle("GET /v1/judicial/verification/custody-chain", &verifyCustodyChainHandler{deps: deps})
	mux.Handle("GET /v1/judicial/verification/background-check", &verifyBackgroundCheckHandler{deps: deps})
	mux.Handle("POST /v1/judicial/verification/appeal-chain", &verifyAppealChainHandler{deps: deps})
	mux.Handle("GET /v1/judicial/verification/key-attestation", &verifyKeyAttestationHandler{deps: deps})
	mux.Handle("POST /v1/judicial/verification/cross-log-proof", &verifyCrossLogProofHandler{deps: deps})
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/judicial/verification/case-status?log_did=...&seq=...
// ─────────────────────────────────────────────────────────────────────

type verifyCaseStatusHandler struct{ deps *Dependencies }

func (h *verifyCaseStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	ctx := r.Context()
	pos, err := caseRootFromQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	state, err := verification.GetCaseStatus(ctx, pos, h.deps.LeafReader, h.deps.Fetcher)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, state)
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/judicial/verification/enforcement-status?log_did=...&seq=...
// ─────────────────────────────────────────────────────────────────────

type verifyEnforcementHandler struct{ deps *Dependencies }

func (h *verifyEnforcementHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	ctx := r.Context()
	pos, err := caseRootFromQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	status, err := verification.CheckEnforcementStatus(ctx, pos, h.deps.LeafReader, h.deps.Fetcher, h.deps.Extractor)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/verification/filing-delegation
// ─────────────────────────────────────────────────────────────────────

type verifyFilingDelegationRequest struct {
	DelegationPointers []logPositionRef `json:"delegation_pointers"`
}

type verifyFilingDelegationHandler struct{ deps *Dependencies }

func (h *verifyFilingDelegationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	ctx := r.Context()
	var req verifyFilingDelegationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.DelegationPointers) == 0 {
		writeError(w, http.StatusBadRequest, "delegation_pointers required")
		return
	}
	//  doesn't expose ScopeEnforcer / target Entry — those
	// are constructed at submit time. The handler runs the
	// previous chain validity portion (cycle detection, signer
	// match) without scope enforcement.
	result, err := verification.VerifyFilingDelegation(
		ctx, toLogPositions(req.DelegationPointers), h.deps.Fetcher, h.deps.LeafReader, nil, nil,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/judicial/verification/custody-chain
// ─────────────────────────────────────────────────────────────────────

type verifyCustodyChainHandler struct{ deps *Dependencies }

func (h *verifyCustodyChainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	cidStr := q.Get("artifact_cid")
	logDID := q.Get("log_did")
	if cidStr == "" || logDID == "" {
		writeError(w, http.StatusBadRequest, "artifact_cid and log_did required")
		return
	}
	startSeq, _ := parseUint64(q.Get("start_seq"))
	maxEntries, err := parseUint64(q.Get("max_entries"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "max_entries must be a uint64")
		return
	}
	if maxEntries == 0 {
		maxEntries = 200
	}
	scanner, ok := h.scannerFor(logDID)
	if !ok {
		writeError(w, http.StatusInternalServerError, "no LogQueries entry for "+logDID)
		return
	}
	chain, err := verification.ReconstructCustodyChain(
		ctx, cidStr, scanner, h.deps.Fetcher, h.deps.LeafReader, logDID, startSeq, int(maxEntries),
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, chain)
}

func (h *verifyCustodyChainHandler) scannerFor(logDID string) (verification.CustodyScanner, bool) {
	q, ok := h.deps.LogQueries[logDID]
	if !ok {
		return nil, false
	}
	return custodyScannerAdapter{api: q}, true
}

// custodyScannerAdapter wraps sdklog.LedgerQueryAPI to satisfy
// verification.CustodyScanner. Both signatures now take ctx in
// v0.3.0; the adapter exists to constrain the embedded api to the
// one method CustodyScanner needs.
type custodyScannerAdapter struct{ api sdklog.LedgerQueryAPI }

func (a custodyScannerAdapter) ScanFromPosition(ctx context.Context, start uint64, count int) ([]types.EntryWithMetadata, error) {
	return a.api.ScanFromPosition(ctx, start, count)
}

// caseRootFromQuery is shared across the verify-* GET handlers that
// take a (log_did, seq) pair as their case root reference.
func caseRootFromQuery(r *http.Request) (types.LogPosition, error) {
	q := r.URL.Query()
	logDID := q.Get("log_did")
	seqStr := q.Get("seq")
	if logDID == "" || seqStr == "" {
		return types.LogPosition{}, errInvalidLogPos
	}
	seq, err := parseUint64(seqStr)
	if err != nil {
		return types.LogPosition{}, errInvalidLogPos
	}
	return types.LogPosition{LogDID: logDID, Sequence: seq}, nil
}

var errInvalidLogPos = newErr("log_did and seq required")

// newErr is a small helper for fixed-message errors used in
// per-handler validation.
func newErr(msg string) error { return errString(msg) }

type errString string

func (e errString) Error() string { return string(e) }
