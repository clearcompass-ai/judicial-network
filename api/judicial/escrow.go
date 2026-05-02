/*
FILE PATH: api/judicial/escrow.go

DESCRIPTION:
    Escrow recovery (Phase 10) — HTTP handlers for the M-of-N
    recovery vocabulary. Wraps escrow/event_builder.go which itself
    wraps migration/ungraceful.go + the SDK's lifecycle/recovery.go
    primitives.

    Wired routes (return BuildResponse / verdict JSON):
      POST /v1/judicial/escrow/recovery/initiate
        → BuildRecoveryRequest (commentary entry; caller signs +
          submits via /v1/entries/submit)
      POST /v1/judicial/escrow/migration/record
        → BuildMigrationRecord (post-recovery audit commentary)

    501 stubs with explicit operational reasoning:
      POST /v1/judicial/escrow/recovery/collect-share
        Multi-request server-side state (shares accumulate across N
        escrow nodes). Operator-tooling drives this — the JN binary
        does not hold per-recovery share state.
      POST /v1/judicial/escrow/recovery/execute
        Reconstructs the 32-byte MasterKey. Returning that material
        in an HTTP response body crosses the SDK identity boundary;
        operator tooling runs the reconstruction in-process.
      POST /v1/judicial/escrow/arbitration/evaluate
        Requires resolved EntryWithMetadata fixtures (escrow
        approvals + witness cosig) AND scope SchemaParameters; both
        are operator-tooling concerns. Stub surfaces the reasoning.
*/
package judicial

import (
	"encoding/json"
	"net/http"

	"github.com/clearcompass-ai/judicial-network/escrow"
)

func registerEscrowRoutes(mux *http.ServeMux, deps *Dependencies) {
	mux.Handle("POST /v1/judicial/escrow/recovery/initiate", &escrowInitiateHandler{deps: deps})
	mux.Handle("POST /v1/judicial/escrow/migration/record", &escrowMigrationRecordHandler{deps: deps})
	mux.Handle("POST /v1/judicial/escrow/recovery/collect-share", &escrowCollectShareHandler{deps: deps})
	mux.Handle("POST /v1/judicial/escrow/recovery/execute", &escrowExecuteHandler{deps: deps})
	mux.Handle("POST /v1/judicial/escrow/arbitration/evaluate", &escrowArbitrateHandler{deps: deps})
}

// ─────────────────────────────────────────────────────────────────────
// initiate-recovery
// ─────────────────────────────────────────────────────────────────────

type escrowInitiateRequest struct {
	Destination       string `json:"destination"`
	CourtDID          string `json:"court_did"`
	FailedExchangeDID string `json:"failed_exchange_did"`
	NewExchangeDID    string `json:"new_exchange_did"`
	EscrowPackageCID  string `json:"escrow_package_cid,omitempty"`
}

type escrowInitiateHandler struct{ deps *Dependencies }

func (h *escrowInitiateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	var req escrowInitiateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" || req.CourtDID == "" ||
		req.FailedExchangeDID == "" || req.NewExchangeDID == "" {
		writeError(w, http.StatusBadRequest,
			"destination, court_did, failed_exchange_did, new_exchange_did all required")
		return
	}
	res, err := escrow.BuildRecoveryRequest(escrow.RecoveryInitiateConfig{
		Destination:       req.Destination,
		CourtDID:          req.CourtDID,
		FailedExchangeDID: req.FailedExchangeDID,
		NewExchangeDID:    req.NewExchangeDID,
		EscrowPackageCID:  req.EscrowPackageCID,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeBuildResponse(w, res.RequestEntry)
}

// ─────────────────────────────────────────────────────────────────────
// migration-record
// ─────────────────────────────────────────────────────────────────────

type escrowMigrationRecordRequest struct {
	Destination       string `json:"destination"`
	CourtDID          string `json:"court_did"`
	FailedExchangeDID string `json:"failed_exchange_did"`
	NewExchangeDID    string `json:"new_exchange_did"`
	RecoveryThreshold int    `json:"recovery_threshold"`
	TriggerCount      int    `json:"trigger_count"`
}

type escrowMigrationRecordHandler struct{ deps *Dependencies }

func (h *escrowMigrationRecordHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	var req escrowMigrationRecordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" || req.FailedExchangeDID == "" || req.NewExchangeDID == "" {
		writeError(w, http.StatusBadRequest,
			"destination, failed_exchange_did, new_exchange_did all required")
		return
	}
	entry, err := escrow.BuildMigrationRecord(escrow.MigrationRecordConfig{
		Destination:       req.Destination,
		SignerDID:         signer,
		CourtDID:          req.CourtDID,
		FailedExchangeDID: req.FailedExchangeDID,
		NewExchangeDID:    req.NewExchangeDID,
		RecoveryThreshold: req.RecoveryThreshold,
		TriggerCount:      req.TriggerCount,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeBuildResponse(w, entry)
}

// ─────────────────────────────────────────────────────────────────────
// 501 stubs — operator-tooling territory
// ─────────────────────────────────────────────────────────────────────

type escrowCollectShareHandler struct{ deps *Dependencies }

func (h *escrowCollectShareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"escrow.CollectShares accumulates per-recovery state across N share submissions; "+
			"operator-tooling holds that state, not the JN HTTP surface")
}

type escrowExecuteHandler struct{ deps *Dependencies }

func (h *escrowExecuteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"escrow.ExecuteRecovery returns 32-byte MasterKey material; that material MUST NOT cross "+
			"the HTTP boundary — operator-tooling runs reconstruction in-process and emits the "+
			"signed Succession Entry directly to /v1/entries/submit")
}

type escrowArbitrateHandler struct{ deps *Dependencies }

func (h *escrowArbitrateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	// Decode-and-discard so the body isn't left dangling on the
	// wire — keeps the 501 contract clean against curl /
	// ApacheBench.
	_ = json.NewDecoder(r.Body).Decode(new(map[string]any))
	writeError(w, http.StatusNotImplemented,
		"escrow.EvaluateArbitration requires resolved EntryWithMetadata fixtures (escrow "+
			"approvals + witness cosig) AND scope SchemaParameters; ops-tooling fetches and "+
			"composes these — call escrow.EvaluateArbitration directly from the ops binary")
}
