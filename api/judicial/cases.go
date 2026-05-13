/*
FILE PATH: api/judicial/cases.go

DESCRIPTION:

	Route registration for cases.* handlers + the simpler
	same-process handlers (initiate, amend, lookup, transfer
	division, transfer county stub). The artifact-bearing handlers
	File and RecordJudicialAction live in cases_filings.go where
	their dependency surface (ContentStore + KeyStore +
	DelegationKeyStore + Resolver) is grouped.

	Daily reality:

	  POST /v1/judicial/cases                          → InitiateCase
	  POST /v1/judicial/cases/{caseRootSeq}/amend      → AmendCase
	  GET  /v1/judicial/cases/{docket}                 → LookupDocket
	  POST /v1/judicial/cases/{caseRootSeq}/transfer/division
	                                                   → TransferDivision
	  POST /v1/judicial/cases/{caseRootSeq}/transfer/county
	                                                   → 501 (deferred to C5;
	                                                     needs cross-log proof
	                                                     composition)
*/
package judicial

import (
	"context"
	"fmt"
	"net/http"

	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/cases"
)

// registerCaseRoutes installs every cases.* handler on mux.
func registerCaseRoutes(mux *http.ServeMux, deps *Dependencies) {
	mux.Handle("POST /v1/judicial/cases", &caseInitiateHandler{deps: deps})
	mux.Handle("POST /v1/judicial/cases/{caseRootSeq}/amend", &caseAmendHandler{deps: deps})
	mux.Handle("POST /v1/judicial/cases/{caseRootSeq}/filings", &caseFilingHandler{deps: deps})
	mux.Handle("POST /v1/judicial/cases/{caseRootSeq}/actions", &caseActionHandler{deps: deps})
	mux.Handle("GET /v1/judicial/cases/{docket}", &caseLookupHandler{deps: deps})
	mux.Handle("POST /v1/judicial/cases/{caseRootSeq}/transfer/division", &caseTransferDivisionHandler{deps: deps})
	mux.Handle("POST /v1/judicial/cases/{caseRootSeq}/transfer/county", &caseTransferCountyHandler{deps: deps})
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/cases
// ─────────────────────────────────────────────────────────────────────

type caseInitiateRequest struct {
	Destination           string         `json:"destination"`
	DocketNumber          string         `json:"docket_number"`
	CaseType              string         `json:"case_type"` // criminal | civil | family | juvenile
	FiledDate             string         `json:"filed_date"`
	SchemaRef             *uint64        `json:"schema_ref,omitempty"`
	SchemaLogDID          string         `json:"schema_log_did,omitempty"`
	ExtraPayload          map[string]any `json:"extra_payload,omitempty"`
	EventTime             int64          `json:"event_time,omitempty"`
	AttestationPolicyName *string        `json:"attestation_policy_name,omitempty"`
}

type caseInitiateHandler struct{ deps *Dependencies }

func (h *caseInitiateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	var req caseInitiateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" {
		writeError(w, http.StatusBadRequest, "destination required")
		return
	}
	cfg := cases.InitiationConfig{
		Destination:           req.Destination,
		SignerDID:             signer,
		DocketNumber:          req.DocketNumber,
		CaseType:              req.CaseType,
		FiledDate:             req.FiledDate,
		ExtraPayload:          req.ExtraPayload,
		EventTime:             req.EventTime,
		AttestationPolicyName: req.AttestationPolicyName,
	}
	if req.SchemaRef != nil && req.SchemaLogDID != "" {
		cfg.SchemaRef = &types.LogPosition{LogDID: req.SchemaLogDID, Sequence: *req.SchemaRef}
	}
	result, err := cases.InitiateCase(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeBuildResponse(w, result.Entry)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/cases/{caseRootSeq}/amend
// ─────────────────────────────────────────────────────────────────────

type caseAmendRequest struct {
	Destination           string           `json:"destination"`
	CaseRootLogDID        string           `json:"case_root_log_did"`
	AmendmentType         string           `json:"amendment_type"` // status_change | reassignment | artifact_update
	NewStatus             string           `json:"new_status,omitempty"`
	NewArtifactCID        string           `json:"new_artifact_cid,omitempty"`
	SchemaRef             *uint64          `json:"schema_ref,omitempty"`
	SchemaLogDID          string           `json:"schema_log_did,omitempty"`
	EvidencePointers      []logPositionRef `json:"evidence_pointers,omitempty"`
	ExtraPayload          map[string]any   `json:"extra_payload,omitempty"`
	EventTime             int64            `json:"event_time,omitempty"`
	AttestationPolicyName *string          `json:"attestation_policy_name,omitempty"`
}

type caseAmendHandler struct{ deps *Dependencies }

func (h *caseAmendHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	var req caseAmendRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" {
		writeError(w, http.StatusBadRequest, "destination required")
		return
	}
	caseRootSeq, ok := pathSeq(r, "caseRootSeq")
	if !ok {
		writeError(w, http.StatusBadRequest, "caseRootSeq must be a uint64")
		return
	}
	if req.CaseRootLogDID == "" {
		writeError(w, http.StatusBadRequest, "case_root_log_did required")
		return
	}
	cfg := cases.AmendmentConfig{
		Destination:           req.Destination,
		SignerDID:             signer,
		CaseRootPos:           types.LogPosition{LogDID: req.CaseRootLogDID, Sequence: caseRootSeq},
		AmendmentType:         req.AmendmentType,
		NewStatus:             req.NewStatus,
		NewArtifactCID:        req.NewArtifactCID,
		EvidencePointers:      toLogPositions(req.EvidencePointers),
		ExtraPayload:          req.ExtraPayload,
		EventTime:             req.EventTime,
		AttestationPolicyName: req.AttestationPolicyName,
	}
	if req.SchemaRef != nil && req.SchemaLogDID != "" {
		cfg.SchemaRef = &types.LogPosition{LogDID: req.SchemaLogDID, Sequence: *req.SchemaRef}
	}
	entry, err := cases.AmendCase(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeBuildResponse(w, entry)
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/judicial/cases/{docket}
// ─────────────────────────────────────────────────────────────────────

type caseLookupHandler struct{ deps *Dependencies }

func (h *caseLookupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	ctx := r.Context()
	docket := r.PathValue("docket")
	if docket == "" {
		writeError(w, http.StatusBadRequest, "docket required")
		return
	}
	scanner, err := h.scannerFor(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	result, err := cases.LookupDocket(ctx, docket, signer, scanner, h.deps.Fetcher, h.deps.LeafReader)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// scannerFor resolves the cases-log query API for the caller. The
// caller MUST send X-Cases-Log-DID; production deployments may
// derive this from the auth context's home-court mapping in a
// future patch.
func (h *caseLookupHandler) scannerFor(r *http.Request) (cases.DocketScanner, error) {
	logDID := r.Header.Get("X-Cases-Log-DID")
	if logDID == "" {
		return nil, fmt.Errorf("X-Cases-Log-DID header required")
	}
	q, ok := h.deps.LogQueries[logDID]
	if !ok {
		return nil, fmt.Errorf("no LogQueries entry for %s", logDID)
	}
	return docketScannerAdapter{ctx: r.Context(), api: q}, nil
}

// docketScannerAdapter bridges a ctx-aware LedgerQueryAPI to the
// ctx-aware cases.DocketScanner contract — both now require ctx in
// v0.3.0, so the adapter is a pass-through that also binds the
// per-request ctx into the underlying RPC.
type docketScannerAdapter struct {
	ctx context.Context
	api interface {
		QueryBySignerDID(ctx context.Context, did string) ([]types.EntryWithMetadata, error)
	}
}

func (a docketScannerAdapter) QueryBySignerDID(ctx context.Context, did string) ([]types.EntryWithMetadata, error) {
	if ctx == nil {
		ctx = a.ctx
	}
	return a.api.QueryBySignerDID(ctx, did)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/cases/{caseRootSeq}/transfer/division
// ─────────────────────────────────────────────────────────────────────

type caseTransferDivisionRequest struct {
	Destination    string  `json:"destination"`
	CaseRootLogDID string  `json:"case_root_log_did"`
	TargetDivision string  `json:"target_division"`
	Reason         string  `json:"reason"`
	SchemaRef      *uint64 `json:"schema_ref,omitempty"`
	SchemaLogDID   string  `json:"schema_log_did,omitempty"`
	EventTime      int64   `json:"event_time,omitempty"`
}

type caseTransferDivisionHandler struct{ deps *Dependencies }

func (h *caseTransferDivisionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	var req caseTransferDivisionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" {
		writeError(w, http.StatusBadRequest, "destination required")
		return
	}
	caseRootSeq, ok := pathSeq(r, "caseRootSeq")
	if !ok {
		writeError(w, http.StatusBadRequest, "caseRootSeq must be a uint64")
		return
	}
	if req.CaseRootLogDID == "" {
		writeError(w, http.StatusBadRequest, "case_root_log_did required")
		return
	}
	cfg := cases.DivisionTransferConfig{
		Destination:    req.Destination,
		SignerDID:      signer,
		CaseRootPos:    types.LogPosition{LogDID: req.CaseRootLogDID, Sequence: caseRootSeq},
		TargetDivision: req.TargetDivision,
		Reason:         req.Reason,
		EventTime:      req.EventTime,
	}
	if req.SchemaRef != nil && req.SchemaLogDID != "" {
		cfg.SchemaRef = &types.LogPosition{LogDID: req.SchemaLogDID, Sequence: *req.SchemaRef}
	}
	entry, err := cases.TransferDivision(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeBuildResponse(w, entry)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/cases/{caseRootSeq}/transfer/county — stub
// ─────────────────────────────────────────────────────────────────────

// cases.TransferCounty's signature requires assembled CrossLogProof
// inputs (source/local Merkle provers, source/local cosigned tree
// heads, anchor refs, delegation querier). Composing those from raw
// HTTP inputs is its own subsystem; wired in C5 alongside the
// CrossLogProofBuilder helper.
type caseTransferCountyHandler struct{ deps *Dependencies }

func (h *caseTransferCountyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"county transfer requires cross-log proof composition; wired in C5")
}
