/*
FILE PATH: api/judicial/enforcement.go

DESCRIPTION:

	Sealing / unsealing / cosignature handlers — the daily reality
	of court enforcement orders that REGULATE access without
	destroying material.

	  POST /v1/judicial/enforcement/seal               → SealCase
	  POST /v1/judicial/enforcement/unseal             → UnsealCase
	  POST /v1/judicial/enforcement/unseal/cosignature → RequestUnsealCosignature
	  GET  /v1/judicial/enforcement/sealing-status     → CheckSealingActivation

	The expungement + evidence-access + compliance handlers (which
	touch the artifact stack and / or read-side authority chains)
	live in enforcement_audit.go.
*/
package judicial

import (
	"net/http"
	"time"

	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/enforcement"
)

// registerEnforcementRoutes installs every enforcement.* handler.
func registerEnforcementRoutes(mux *http.ServeMux, deps *Dependencies) {
	mux.Handle("POST /v1/judicial/enforcement/seal", &sealHandler{deps: deps})
	mux.Handle("POST /v1/judicial/enforcement/unseal", &unsealHandler{deps: deps})
	mux.Handle("POST /v1/judicial/enforcement/unseal/cosignature", &unsealCosignatureHandler{deps: deps})
	mux.Handle("GET /v1/judicial/enforcement/sealing-status", &sealingStatusHandler{deps: deps})
	mux.Handle("POST /v1/judicial/enforcement/expunge", &expungeHandler{deps: deps})
	mux.Handle("POST /v1/judicial/enforcement/evidence-access", &evidenceAccessHandler{deps: deps})
	mux.Handle("GET /v1/judicial/enforcement/compliance", &complianceHandler{deps: deps})
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/enforcement/seal
// ─────────────────────────────────────────────────────────────────────

// sealRequest mirrors enforcement.SealingConfig in JSON shape. Daily
// reality: a judge orders a record sealed (juvenile case, victim
// protection, ongoing investigation). The seal is enforced via Path C
// authority advancement on the case leaf — once submitted, every
// downstream retrieve sees ErrSealed.
type sealRequest struct {
	Destination    string          `json:"destination"`
	CaseRootLogDID string          `json:"case_root_log_did"`
	CaseRootSeq    uint64          `json:"case_root_seq"`
	ScopeLogDID    string          `json:"scope_log_did"`
	ScopeSeq       uint64          `json:"scope_seq"`
	PriorAuthority *logPositionRef `json:"prior_authority,omitempty"`
	SchemaRef      *uint64         `json:"schema_ref,omitempty"`
	SchemaLogDID   string          `json:"schema_log_did,omitempty"`
	OrderType      string          `json:"order_type"` // seal | unseal | auto_seal
	Authority      string          `json:"authority"`  // TCA citation
	Reason         string          `json:"reason"`
	ArtifactCIDs   []string        `json:"artifact_cids,omitempty"`
	EventTime      int64           `json:"event_time,omitempty"`
}

type sealHandler struct{ deps *Dependencies }

func (h *sealHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	judge := requireCaller(w, r)
	if judge == "" {
		return
	}
	var req sealRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" {
		writeError(w, http.StatusBadRequest, "destination required")
		return
	}
	cfg := enforcement.SealingConfig{
		Destination:  req.Destination,
		JudgeDID:     judge,
		CaseRootPos:  types.LogPosition{LogDID: req.CaseRootLogDID, Sequence: req.CaseRootSeq},
		ScopePos:     types.LogPosition{LogDID: req.ScopeLogDID, Sequence: req.ScopeSeq},
		OrderType:    req.OrderType,
		Authority:    req.Authority,
		Reason:       req.Reason,
		ArtifactCIDs: req.ArtifactCIDs,
		EventTime:    req.EventTime,
	}
	if req.PriorAuthority != nil {
		pa := req.PriorAuthority.toLogPosition()
		cfg.PriorAuthority = &pa
	}
	if req.SchemaRef != nil && req.SchemaLogDID != "" {
		cfg.SchemaRef = &types.LogPosition{LogDID: req.SchemaLogDID, Sequence: *req.SchemaRef}
	}
	result, err := enforcement.SealCase(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeBuildResponse(w, result.EnforcementEntry)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/enforcement/unseal
// ─────────────────────────────────────────────────────────────────────

// Unsealing requires cosignature_threshold=1 per tn-sealing-order-v1.
// This handler builds the unsealing PROPOSAL; the cosignature is
// collected via the /unseal/cosignature endpoint.
type unsealRequest struct {
	Destination    string          `json:"destination"`
	CaseRootLogDID string          `json:"case_root_log_did"`
	CaseRootSeq    uint64          `json:"case_root_seq"`
	ScopeLogDID    string          `json:"scope_log_did"`
	ScopeSeq       uint64          `json:"scope_seq"`
	PriorAuthority *logPositionRef `json:"prior_authority,omitempty"`
	SchemaRef      *uint64         `json:"schema_ref,omitempty"`
	SchemaLogDID   string          `json:"schema_log_did,omitempty"`
	Reason         string          `json:"reason"`
	EventTime      int64           `json:"event_time,omitempty"`
}

type unsealHandler struct{ deps *Dependencies }

func (h *unsealHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	judge := requireCaller(w, r)
	if judge == "" {
		return
	}
	var req unsealRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" {
		writeError(w, http.StatusBadRequest, "destination required")
		return
	}
	cfg := enforcement.UnsealingConfig{
		Destination: req.Destination,
		JudgeDID:    judge,
		CaseRootPos: types.LogPosition{LogDID: req.CaseRootLogDID, Sequence: req.CaseRootSeq},
		ScopePos:    types.LogPosition{LogDID: req.ScopeLogDID, Sequence: req.ScopeSeq},
		Reason:      req.Reason,
		EventTime:   req.EventTime,
	}
	if req.PriorAuthority != nil {
		pa := req.PriorAuthority.toLogPosition()
		cfg.PriorAuthority = &pa
	}
	if req.SchemaRef != nil && req.SchemaLogDID != "" {
		cfg.SchemaRef = &types.LogPosition{LogDID: req.SchemaLogDID, Sequence: *req.SchemaRef}
	}
	result, err := enforcement.UnsealCase(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeBuildResponse(w, result.EnforcementEntry)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/enforcement/unseal/cosignature
// ─────────────────────────────────────────────────────────────────────

// A second judge cosigns an unsealing proposal. The caller's DID is
// the cosigner. unsealingEntryPos is the proposal entry's log
// position from the original /unseal call's response.
type unsealCosignatureRequest struct {
	Destination     string `json:"destination"`
	UnsealingLogDID string `json:"unsealing_log_did"`
	UnsealingSeq    uint64 `json:"unsealing_seq"`
	EventTime       int64  `json:"event_time,omitempty"`
}

type unsealCosignatureHandler struct{ deps *Dependencies }

func (h *unsealCosignatureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cosigner := requireCaller(w, r)
	if cosigner == "" {
		return
	}
	var req unsealCosignatureRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" || req.UnsealingLogDID == "" {
		writeError(w, http.StatusBadRequest, "destination and unsealing_log_did required")
		return
	}
	entry, err := enforcement.RequestUnsealCosignature(
		cosigner, req.Destination,
		types.LogPosition{LogDID: req.UnsealingLogDID, Sequence: req.UnsealingSeq},
		req.EventTime,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeBuildResponse(w, entry)
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/judicial/enforcement/sealing-status?log_did=...&seq=...
// ─────────────────────────────────────────────────────────────────────

// Read-side: did a pending sealing entry collect enough cosignatures
// to activate? Used by clerks polling for the moment the seal becomes
// effective.
type sealingStatusHandler struct{ deps *Dependencies }

func (h *sealingStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	logDID := r.URL.Query().Get("log_did")
	seqStr := r.URL.Query().Get("seq")
	if logDID == "" || seqStr == "" {
		writeError(w, http.StatusBadRequest, "log_did and seq required")
		return
	}
	var seq uint64
	if _, err := fmtSscan(seqStr, &seq); err != nil {
		writeError(w, http.StatusBadRequest, "seq must be a uint64")
		return
	}
	pos := types.LogPosition{LogDID: logDID, Sequence: seq}
	// nil cosigs / querier → CheckSealingActivation resolves the
	// cosignature condition as 0/N. Production deployments may hand
	// in a CosignatureQuerier-backed Dependencies field when the
	// composer is wired with a richer query layer; for  first
	// cut we trust the entry's existing cosigs in the leaf.
	status, err := enforcement.CheckSealingActivation(
		pos, h.deps.Fetcher, h.deps.LeafReader, h.deps.Extractor,
		time.Now().UTC(), nil, nil,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// fmtSscan is an indirection over fmt.Sscan so callers don't import
// fmt directly here; simpler unit testing.
func fmtSscan(s string, v *uint64) (int, error) {
	return sscanU64(s, v)
}
