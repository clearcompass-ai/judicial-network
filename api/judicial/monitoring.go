/*
FILE PATH: api/judicial/monitoring.go

DESCRIPTION:
    Monitoring handlers — operational-visibility checks the court ops
    team runs to detect drift, broken delegations, missing artifacts.

      POST /v1/judicial/monitoring/blob-availability   → CheckBlobAvailability
      POST /v1/judicial/monitoring/delegation-health   → CheckDelegationHealth
      GET  /v1/judicial/monitoring/anchor-freshness    → 501 (witness deps)

    Compliance-side (dual-attestation, mirror-consistency, sealing-
    compliance, grant-compliance, shard-health, dashboard) lives in
    monitoring_compliance.go.
*/
package judicial

import (
	"net/http"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/witness"

	"github.com/clearcompass-ai/judicial-network/monitoring"
)

func registerMonitoringRoutes(mux *http.ServeMux, deps *Dependencies) {
	mux.Handle("POST /v1/judicial/monitoring/blob-availability", &monBlobAvailHandler{deps: deps})
	mux.Handle("POST /v1/judicial/monitoring/delegation-health", &monDelegationHealthHandler{deps: deps})
	mux.Handle("GET /v1/judicial/monitoring/anchor-freshness", &monAnchorFreshnessHandler{deps: deps})
	mux.Handle("POST /v1/judicial/monitoring/dual-attestation", &monDualAttestationHandler{deps: deps})
	mux.Handle("POST /v1/judicial/monitoring/mirror-consistency", &monMirrorConsistencyHandler{deps: deps})
	mux.Handle("POST /v1/judicial/monitoring/sealing-compliance", &monSealingComplianceHandler{deps: deps})
	mux.Handle("POST /v1/judicial/monitoring/grant-compliance", &monGrantComplianceHandler{deps: deps})
	mux.Handle("POST /v1/judicial/monitoring/dashboard", &monDashboardHandler{deps: deps})
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/monitoring/blob-availability
// ─────────────────────────────────────────────────────────────────────

type monBlobAvailRequest struct {
	ExpectedPresent []string `json:"expected_present,omitempty"`
	ExpectedAbsent  []string `json:"expected_absent,omitempty"`
	Backend         string   `json:"backend"`
}

type monBlobAvailHandler struct{ deps *Dependencies }

func (h *monBlobAvailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	if h.deps.ContentStore == nil {
		writeError(w, http.StatusInternalServerError, "ContentStore not configured")
		return
	}
	var req monBlobAvailRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cfg := monitoring.BlobCheckConfig{Backend: req.Backend}
	for _, raw := range req.ExpectedPresent {
		c, err := storage.ParseCID(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expected_present CID: "+raw)
			return
		}
		cfg.ExpectedPresent = append(cfg.ExpectedPresent, c)
	}
	for _, raw := range req.ExpectedAbsent {
		c, err := storage.ParseCID(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expected_absent CID: "+raw)
			return
		}
		cfg.ExpectedAbsent = append(cfg.ExpectedAbsent, c)
	}
	result, err := monitoring.CheckBlobAvailability(cfg, h.deps.ContentStore, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/monitoring/delegation-health
// ─────────────────────────────────────────────────────────────────────

type monDelegationHealthRequest struct {
	LocalLogDID    string         `json:"local_log_did"`
	OfficersLogDID string         `json:"officers_log_did"`
	RootEntityPos  logPositionRef `json:"root_entity_pos"`
	ScanLookback   int            `json:"scan_lookback,omitempty"`
	ScanStartSeq   uint64         `json:"scan_start_seq,omitempty"`
}

type monDelegationHealthHandler struct{ deps *Dependencies }

func (h *monDelegationHealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	var req monDelegationHealthRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.LocalLogDID == "" || req.OfficersLogDID == "" {
		writeError(w, http.StatusBadRequest, "local_log_did and officers_log_did required")
		return
	}
	api, ok := h.deps.LogQueries[req.LocalLogDID]
	if !ok {
		writeError(w, http.StatusInternalServerError, "no LogQueries entry for "+req.LocalLogDID)
		return
	}
	cfg := monitoring.DelegationHealthConfig{
		LocalLogDID:    req.LocalLogDID,
		OfficersLogDID: req.OfficersLogDID,
		RootEntityPos:  req.RootEntityPos.toLogPosition(),
		ScanLookback:   req.ScanLookback,
		ScanStartSeq:   req.ScanStartSeq,
	}
	alerts, err := monitoring.CheckDelegationHealth(cfg, api, h.deps.Fetcher, h.deps.LeafReader, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, alerts)
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/judicial/monitoring/anchor-freshness
// ─────────────────────────────────────────────────────────────────────

// monAnchorFreshnessHandler wraps monitoring.CheckAnchorFreshness.
// Reads the local + parent log DIDs, anchor cadence, and operator
// signer DID from query params; uses Dependencies.LogQueries +
// TreeHeadClient. 503 when TreeHeadClient is unconfigured.
type monAnchorFreshnessHandler struct{ deps *Dependencies }

func (h *monAnchorFreshnessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	if h.deps.TreeHeadClient == nil {
		writeError(w, http.StatusServiceUnavailable,
			"monitoring.anchor-freshness requires a configured *witness.TreeHeadClient; "+
				"populate witness operational config + restart")
		return
	}
	q := r.URL.Query()
	localLogDID := q.Get("local_log_did")
	parentLogDID := q.Get("parent_log_did")
	operatorSignerDID := q.Get("operator_signer_did")
	if localLogDID == "" || parentLogDID == "" || operatorSignerDID == "" {
		writeError(w, http.StatusBadRequest,
			"local_log_did, parent_log_did, operator_signer_did all required")
		return
	}
	queryAPI, ok := h.deps.LogQueries[localLogDID]
	if !ok || queryAPI == nil {
		writeError(w, http.StatusInternalServerError,
			"no log query API for "+localLogDID)
		return
	}
	cfg := monitoring.AnchorFreshnessConfig{
		LocalLogDID:          localLogDID,
		ParentLogDID:         parentLogDID,
		OperatorSignerDID:    operatorSignerDID,
		AnchorIntervalTarget: parseDurationDefault(q.Get("interval_target"), time.Hour),
		WarningThreshold:     parseDurationDefault(q.Get("warning_threshold"), 90*time.Minute),
		CriticalThreshold:    parseDurationDefault(q.Get("critical_threshold"), 3*time.Hour),
		ParentStaleness:      witness.StalenessMonitoring,
	}
	alerts, err := monitoring.CheckAnchorFreshness(cfg, queryAPI, h.deps.TreeHeadClient, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

// parseDurationDefault returns time.ParseDuration(s) or fallback
// when s is empty / unparseable.
func parseDurationDefault(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

// queryAPIFor resolves an OperatorQueryAPI from Dependencies.LogQueries.
// Used by every monitoring handler that scans a single log.
func (deps *Dependencies) queryAPIFor(logDID string) (interface {
	QueryBySignerDID(did string) ([]types.EntryWithMetadata, error)
}, bool) {
	api, ok := deps.LogQueries[logDID]
	if !ok {
		return nil, false
	}
	return api, true
}
