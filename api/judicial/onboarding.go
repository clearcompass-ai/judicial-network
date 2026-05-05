/*
FILE PATH: api/judicial/onboarding.go

DESCRIPTION:

	Onboarding handlers — bootstrap events at court setup time. Most
	are operationally specialized (bulk bootstrap scripts hold this
	responsibility, not curl), so several appear as 501 stubs.

	  POST /v1/judicial/onboarding/schema-adoption    → AdoptSchema
	  POST /v1/judicial/onboarding/court-provision    → 501 (operations script)
	  POST /v1/judicial/onboarding/anchor-registration → 501 (witness deps)
	  POST /v1/judicial/onboarding/migrate-records    → 501 (artifact stack;
	                                                    see C4 for the artifact
	                                                    composition pattern)

	Schema adoption is the only daily-ish onboarding event (a court
	pulls a schema published by a parent jurisdiction). The other
	three are one-time bootstraps owned by ops tooling.
*/
package judicial

import (
	"net/http"

	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/onboarding"
)

func registerOnboardingRoutes(mux *http.ServeMux, deps *Dependencies) {
	mux.Handle("POST /v1/judicial/onboarding/schema-adoption", &schemaAdoptHandler{deps: deps})
	mux.Handle("POST /v1/judicial/onboarding/court-provision", &courtProvisionHandler{deps: deps})
	mux.Handle("POST /v1/judicial/onboarding/anchor-registration", &anchorRegistrationHandler{deps: deps})
	mux.Handle("POST /v1/judicial/onboarding/migrate-records", &migrateRecordsHandler{deps: deps})
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/onboarding/schema-adoption
// ─────────────────────────────────────────────────────────────────────

// AdoptSchema fetches a schema entry from a source log, verifies it,
// and prepares a local commentary entry adopting the schema. Daily
// reality: a county court adopting a state-published schema upgrade.
type schemaAdoptRequest struct {
	Destination        string  `json:"destination"`
	SourceSchemaLogDID string  `json:"source_schema_log_did"`
	SourceSchemaSeq    uint64  `json:"source_schema_seq"`
	HistoricalLogDID   string  `json:"historical_log_did,omitempty"`
	HistoricalSeq      *uint64 `json:"historical_seq,omitempty"`
	EventTime          int64   `json:"event_time,omitempty"`
}

type schemaAdoptHandler struct{ deps *Dependencies }

func (h *schemaAdoptHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	var req schemaAdoptRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" || req.SourceSchemaLogDID == "" {
		writeError(w, http.StatusBadRequest, "destination and source_schema_log_did required")
		return
	}
	cfg := onboarding.SchemaAdoptionConfig{
		Destination:     req.Destination,
		LocalSignerDID:  signer,
		SourceSchemaRef: types.LogPosition{LogDID: req.SourceSchemaLogDID, Sequence: req.SourceSchemaSeq},
		EventTime:       req.EventTime,
	}
	if req.HistoricalSeq != nil && req.HistoricalLogDID != "" {
		cfg.HistoricalReference = types.LogPosition{
			LogDID: req.HistoricalLogDID, Sequence: *req.HistoricalSeq,
		}
	}
	report, err := onboarding.AdoptSchema(cfg, h.deps.Fetcher, h.deps.Extractor)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// ─────────────────────────────────────────────────────────────────────
// 501 stubs — bootstrap events owned by ops tooling
// ─────────────────────────────────────────────────────────────────────

// ProvisionCourt's CourtProvisionConfig requires a *topology.SpokeConfig,
// AuthoritySet map, []InitialOfficer, and a *schemas.Registry. Marshalling
// all of that across HTTP for a one-time bootstrap is operationally
// specialized; production deployments run this from a dedicated
// onboarding tool with the artifacts the script generates submitted
// through /v1/entries/submit on api/exchange.
type courtProvisionHandler struct{ deps *Dependencies }

func (h *courtProvisionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"court provisioning is bootstrap-script-driven; submit the entries directly to /v1/entries/submit")
}

// RegisterFirstAnchor needs a *witness.TreeHeadClient — federation
// boot, owned by the federation ledger's tooling rather than HTTP.
type anchorRegistrationHandler struct{ deps *Dependencies }

func (h *anchorRegistrationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"anchor registration requires *witness.TreeHeadClient injection; run via federation tool")
}

// MigrateLegacyRecords is a bulk-import that ingests N records,
// each with its own filing + amendment + artifact-publish flow. The
// per-record path is fully wired in C4 (artifacts) for individual
// curls; bulk migration is best handled by a dedicated importer
// that re-uses C4's per-record flow plus rate limiting.
type migrateRecordsHandler struct{ deps *Dependencies }

func (h *migrateRecordsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"bulk migration is importer-driven; per-record paths arrive in C4")
}
