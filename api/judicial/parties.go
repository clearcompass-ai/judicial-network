/*
FILE PATH: api/judicial/parties.go

DESCRIPTION:

	Party-binding handlers — every plaintiff, defendant, respondent,
	petitioner, or state-actor side gets a binding entry on the
	parties log when the case is filed.

	  POST /v1/judicial/parties/bindings              → CreateBinding
	  PATCH /v1/judicial/parties/bindings/{seq}/status → UpdateBinding
	  POST /v1/judicial/parties/case-links            → LinkPartyToCase

	Sealed bindings (artifact-bearing) live in parties_sealed.go;
	queries (list, find-by-binding-id) live in parties_query.go.
*/
package judicial

import (
	"net/http"

	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/parties"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

func registerPartiesRoutes(mux *http.ServeMux, deps *Dependencies) {
	mux.Handle("POST /v1/judicial/parties/bindings", &partyBindingCreateHandler{deps: deps})
	mux.Handle("PATCH /v1/judicial/parties/bindings/{seq}/status", &partyBindingUpdateHandler{deps: deps})
	mux.Handle("POST /v1/judicial/parties/case-links", &partyCaseLinkHandler{deps: deps})
	mux.Handle("POST /v1/judicial/parties/bindings/sealed", &partyBindingSealedHandler{deps: deps})
	mux.Handle("GET /v1/judicial/parties/bindings", &partyBindingListHandler{deps: deps})
	mux.Handle("GET /v1/judicial/parties/bindings/by-id/{bindingID}", &partyBindingFindHandler{deps: deps})
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/parties/bindings
// ─────────────────────────────────────────────────────────────────────

type partyBindingCreateRequest struct {
	Destination  string  `json:"destination"`
	BindingID    string  `json:"binding_id"`
	PartyClass   string  `json:"party_class"` // plaintiff | defendant | respondent | petitioner | state
	PartyName    string  `json:"party_name,omitempty"`
	CaseRef      string  `json:"case_ref"`
	CaseDID      string  `json:"case_did,omitempty"`
	CaseSeq      uint64  `json:"case_seq,omitempty"`
	SchemaRef    *uint64 `json:"schema_ref,omitempty"`
	SchemaLogDID string  `json:"schema_log_did,omitempty"`
	EventTime    int64   `json:"event_time,omitempty"`
}

type partyBindingCreateHandler struct{ deps *Dependencies }

func (h *partyBindingCreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	var req partyBindingCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" {
		writeError(w, http.StatusBadRequest, "destination required")
		return
	}
	cfg := parties.BindingConfig{
		Destination: req.Destination,
		SignerDID:   signer,
		BindingID:   req.BindingID,
		PartyClass:  schemas.PartyClass(req.PartyClass),
		PartyName:   req.PartyName,
		CaseRef:     req.CaseRef,
		CaseDID:     req.CaseDID,
		CaseSeq:     req.CaseSeq,
		EventTime:   req.EventTime,
	}
	if req.SchemaRef != nil && req.SchemaLogDID != "" {
		cfg.SchemaRef = &types.LogPosition{LogDID: req.SchemaLogDID, Sequence: *req.SchemaRef}
	}
	result, err := parties.CreateBinding(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := struct {
		buildResponse
		Payload any `json:"payload,omitempty"`
	}{Payload: result.Payload}
	writeBuildResponseTo(&resp.buildResponse, result.Entry)
	writeJSON(w, http.StatusOK, resp)
}

// ─────────────────────────────────────────────────────────────────────
// PATCH /v1/judicial/parties/bindings/{seq}/status
// ─────────────────────────────────────────────────────────────────────

type partyBindingUpdateRequest struct {
	Destination   string  `json:"destination"`
	BindingLogDID string  `json:"binding_log_did"`
	NewStatus     string  `json:"new_status"` // active | withdrawn | dismissed
	SchemaRef     *uint64 `json:"schema_ref,omitempty"`
	SchemaLogDID  string  `json:"schema_log_did,omitempty"`
	EventTime     int64   `json:"event_time,omitempty"`
}

type partyBindingUpdateHandler struct{ deps *Dependencies }

func (h *partyBindingUpdateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	var req partyBindingUpdateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" || req.BindingLogDID == "" {
		writeError(w, http.StatusBadRequest, "destination and binding_log_did required")
		return
	}
	bindingSeq, ok := pathSeq(r, "seq")
	if !ok {
		writeError(w, http.StatusBadRequest, "seq must be a uint64")
		return
	}
	cfg := parties.UpdateBindingConfig{
		Destination: req.Destination,
		SignerDID:   signer,
		BindingPos:  types.LogPosition{LogDID: req.BindingLogDID, Sequence: bindingSeq},
		NewStatus:   req.NewStatus,
		EventTime:   req.EventTime,
	}
	if req.SchemaRef != nil && req.SchemaLogDID != "" {
		cfg.SchemaRef = &types.LogPosition{LogDID: req.SchemaLogDID, Sequence: *req.SchemaRef}
	}
	entry, err := parties.UpdateBinding(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeBuildResponse(w, entry)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/parties/case-links
// ─────────────────────────────────────────────────────────────────────

// Daily reality: when a case is filed, every party binding gets a
// commentary entry on the cases log linking the binding to the case
// root. Cross-log: parties log → cases log.
type partyCaseLinkRequest struct {
	Destination    string `json:"destination"`
	CaseRootLogDID string `json:"case_root_log_did"`
	CaseRootSeq    uint64 `json:"case_root_seq"`
	BindingLogDID  string `json:"binding_log_did"`
	BindingSeq     uint64 `json:"binding_seq"`
	BindingID      string `json:"binding_id"`
	PartiesLogDID  string `json:"parties_log_did"`
	PartyClass     string `json:"party_class"`
	EventTime      int64  `json:"event_time,omitempty"`
}

type partyCaseLinkHandler struct{ deps *Dependencies }

func (h *partyCaseLinkHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	var req partyCaseLinkRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" || req.PartiesLogDID == "" {
		writeError(w, http.StatusBadRequest, "destination and parties_log_did required")
		return
	}
	cfg := parties.LinkPartyCaseConfig{
		Destination:   req.Destination,
		SignerDID:     signer,
		CaseRootPos:   types.LogPosition{LogDID: req.CaseRootLogDID, Sequence: req.CaseRootSeq},
		BindingPos:    types.LogPosition{LogDID: req.BindingLogDID, Sequence: req.BindingSeq},
		BindingID:     req.BindingID,
		PartiesLogDID: req.PartiesLogDID,
		PartyClass:    schemas.PartyClass(req.PartyClass),
		EventTime:     req.EventTime,
	}
	entry, err := parties.LinkPartyToCase(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeBuildResponse(w, entry)
}
