/*
FILE PATH: api/judicial/monitoring_compliance.go

DESCRIPTION:
    Compliance-side monitoring handlers — multi-log integrity checks
    for ops dashboards.

      POST /v1/judicial/monitoring/dual-attestation     → CheckDualAttestation
      POST /v1/judicial/monitoring/mirror-consistency   → CheckMirrorConsistency
      POST /v1/judicial/monitoring/sealing-compliance   → CheckSealingCompliance
      POST /v1/judicial/monitoring/grant-compliance     → CheckGrantCompliance
      POST /v1/judicial/monitoring/dashboard            → BuildDashboard
*/
package judicial

import (
	"net/http"
	"time"

	"github.com/clearcompass-ai/judicial-network/monitoring"
)

// ─────────────────────────────────────────────────────────────────────
// dual-attestation
// ─────────────────────────────────────────────────────────────────────

type monDualAttestationRequest struct {
	LogDID           string         `json:"log_did"`
	RootEntityPos    logPositionRef `json:"root_entity_pos"`
	MinimumAttesters int            `json:"minimum_attesters,omitempty"`
}

type monDualAttestationHandler struct{ deps *Dependencies }

func (h *monDualAttestationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	var req monDualAttestationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.LogDID == "" {
		writeError(w, http.StatusBadRequest, "log_did required")
		return
	}
	api, ok := h.deps.LogQueries[req.LogDID]
	if !ok {
		writeError(w, http.StatusInternalServerError, "no LogQueries entry for "+req.LogDID)
		return
	}
	cfg := monitoring.DualAttestationConfig{
		RootEntityPos:    req.RootEntityPos.toLogPosition(),
		MinimumAttesters: req.MinimumAttesters,
	}
	alerts, err := monitoring.CheckDualAttestation(cfg, api, h.deps.Fetcher, h.deps.LeafReader, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, alerts)
}

// ─────────────────────────────────────────────────────────────────────
// mirror-consistency (officers log + cases log; two queriers)
// ─────────────────────────────────────────────────────────────────────

type monMirrorConsistencyRequest struct {
	OfficersLogDID  string         `json:"officers_log_did"`
	CasesLogDID     string         `json:"cases_log_did"`
	MirrorSignerDID string         `json:"mirror_signer_did"`
	RootEntityPos   logPositionRef `json:"root_entity_pos"`
}

type monMirrorConsistencyHandler struct{ deps *Dependencies }

func (h *monMirrorConsistencyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	var req monMirrorConsistencyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.OfficersLogDID == "" || req.CasesLogDID == "" {
		writeError(w, http.StatusBadRequest, "officers_log_did and cases_log_did required")
		return
	}
	officers, ok := h.deps.LogQueries[req.OfficersLogDID]
	if !ok {
		writeError(w, http.StatusInternalServerError, "no LogQueries for "+req.OfficersLogDID)
		return
	}
	cases, ok := h.deps.LogQueries[req.CasesLogDID]
	if !ok {
		writeError(w, http.StatusInternalServerError, "no LogQueries for "+req.CasesLogDID)
		return
	}
	cfg := monitoring.MirrorConsistencyConfig{
		RootEntityPos:   req.RootEntityPos.toLogPosition(),
		OfficersLogDID:  req.OfficersLogDID,
		CasesLogDID:     req.CasesLogDID,
		MirrorSignerDID: req.MirrorSignerDID,
	}
	alerts, err := monitoring.CheckMirrorConsistency(
		cfg, officers, cases, h.deps.Fetcher, h.deps.LeafReader, time.Now().UTC(),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, alerts)
}

// ─────────────────────────────────────────────────────────────────────
// sealing-compliance
// ─────────────────────────────────────────────────────────────────────

type monSealingComplianceRequest struct {
	LocalLogDID  string `json:"local_log_did"`
	ScanStartSeq uint64 `json:"scan_start_seq"`
	ScanCount    int    `json:"scan_count"`
	OverdueSlackSeconds int64 `json:"overdue_slack_seconds,omitempty"`
}

type monSealingComplianceHandler struct{ deps *Dependencies }

func (h *monSealingComplianceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	var req monSealingComplianceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.LocalLogDID == "" {
		writeError(w, http.StatusBadRequest, "local_log_did required")
		return
	}
	api, ok := h.deps.LogQueries[req.LocalLogDID]
	if !ok {
		writeError(w, http.StatusInternalServerError, "no LogQueries for "+req.LocalLogDID)
		return
	}
	cfg := monitoring.SealingComplianceConfig{
		LocalLogDID:  req.LocalLogDID,
		ScanStartSeq: req.ScanStartSeq,
		ScanCount:    req.ScanCount,
		OverdueSlack: time.Duration(req.OverdueSlackSeconds) * time.Second,
	}
	alerts, err := monitoring.CheckSealingCompliance(
		cfg, api, h.deps.Fetcher, h.deps.LeafReader, h.deps.Extractor, time.Now().UTC(),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, alerts)
}

// ─────────────────────────────────────────────────────────────────────
// grant-compliance
// ─────────────────────────────────────────────────────────────────────

type monGrantComplianceRequest struct {
	Destination       string `json:"destination"`
	LocalLogDID       string `json:"local_log_did"`
	ScanStartSeq      uint64 `json:"scan_start_seq"`
	ScanCount         int    `json:"scan_count"`
	AttesterSignerDID string `json:"attester_signer_did,omitempty"`
}

type monGrantComplianceHandler struct{ deps *Dependencies }

func (h *monGrantComplianceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	var req monGrantComplianceRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.LocalLogDID == "" {
		writeError(w, http.StatusBadRequest, "local_log_did required")
		return
	}
	api, ok := h.deps.LogQueries[req.LocalLogDID]
	if !ok {
		writeError(w, http.StatusInternalServerError, "no LogQueries for "+req.LocalLogDID)
		return
	}
	cfg := monitoring.GrantComplianceConfig{
		Destination:       req.Destination,
		LocalLogDID:       req.LocalLogDID,
		ScanStartSeq:      req.ScanStartSeq,
		ScanCount:         req.ScanCount,
		AttesterSignerDID: req.AttesterSignerDID,
	}
	result, err := monitoring.CheckGrantCompliance(
		cfg, api, h.deps.Fetcher, h.deps.LeafReader, h.deps.Extractor, time.Now().UTC(),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ─────────────────────────────────────────────────────────────────────
// dashboard
// ─────────────────────────────────────────────────────────────────────

// BuildDashboard reduces per-court monitor results to a NetworkHealth
// view. Caller posts a map of courtDID → []MonitorResult (decoded
// as raw JSON to avoid leaking the monitoring package's struct here).
type monDashboardRequest struct {
	PerCourt map[string][]monitoring.MonitorResult `json:"per_court"`
}

type monDashboardHandler struct{ deps *Dependencies }

func (h *monDashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	var req monDashboardRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.PerCourt) == 0 {
		writeError(w, http.StatusBadRequest, "per_court required")
		return
	}
	dash := monitoring.BuildDashboard(req.PerCourt, time.Now().UTC())
	writeJSON(w, http.StatusOK, dash)
}
