/*
FILE PATH: api/judicial/appeals.go

DESCRIPTION:
    Appellate handlers — the wired (non-cross-log) ones. Daily reality
    of an appellate court:

      POST /v1/judicial/appeals/decisions          → RecordDecision
      POST /v1/judicial/appeals/mandates/affirm    → IssueMandateAffirm

    The cross-log paths (FileAppeal, IssueMandateReverse,
    TransferRecord) live in appeals_crosslog.go behind 501 stubs
    deferred to C5 alongside the CrossLogProofBuilder helper.

    RecordDecision is artifact-bearing: an appellate panel's opinion
    is published as a Plaintext attachment, encrypted on the way
    through. Affirm mandate is plain (no enforcement on the lower
    court — the case stands).
*/
package judicial

import (
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/appeals"
)

// registerAppealsRoutes installs every appeals.* handler.
func registerAppealsRoutes(mux *http.ServeMux, deps *Dependencies) {
	mux.Handle("POST /v1/judicial/appeals/decisions", &appealDecisionHandler{deps: deps})
	mux.Handle("POST /v1/judicial/appeals/mandates/affirm", &appealMandateAffirmHandler{deps: deps})
	mux.Handle("POST /v1/judicial/appeals/initiations", &appealInitiateHandler{deps: deps})
	mux.Handle("POST /v1/judicial/appeals/mandates/reverse", &appealMandateReverseHandler{deps: deps})
	mux.Handle("POST /v1/judicial/appeals/records/transfer", &appealRecordTransferHandler{deps: deps})
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/appeals/decisions
// ─────────────────────────────────────────────────────────────────────

type appealDecisionRequest struct {
	Destination        string           `json:"destination"`
	AppealCaseLogDID   string           `json:"appeal_case_log_did"`
	AppealCaseSeq      uint64           `json:"appeal_case_seq"`
	CandidatePositions []logPositionRef `json:"candidate_positions,omitempty"`
	Outcome            string           `json:"outcome"` // affirm | reverse | remand | dismiss
	OpinionPlaintextB64 string          `json:"opinion_plaintext_b64,omitempty"`
	SchemaRef          uint64           `json:"schema_ref"`
	SchemaLogDID       string           `json:"schema_log_did"`
	RemandInstructions string           `json:"remand_instructions,omitempty"`
	EventTime          int64            `json:"event_time,omitempty"`
}

type appealDecisionHandler struct{ deps *Dependencies }

func (h *appealDecisionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	judge := requireCaller(w, r)
	if judge == "" {
		return
	}
	var req appealDecisionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" || req.AppealCaseLogDID == "" {
		writeError(w, http.StatusBadRequest, "destination and appeal_case_log_did required")
		return
	}
	plaintext, err := decodeBase64(req.OpinionPlaintextB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "opinion_plaintext_b64 must be valid base64")
		return
	}
	cfg := appeals.DecisionConfig{
		Destination:        req.Destination,
		JudgeDID:           judge,
		AppealCaseRootPos:  types.LogPosition{LogDID: req.AppealCaseLogDID, Sequence: req.AppealCaseSeq},
		CandidatePositions: toLogPositions(req.CandidatePositions),
		Outcome:            req.Outcome,
		OpinionPlaintext:   plaintext,
		SchemaRef:          types.LogPosition{LogDID: req.SchemaLogDID, Sequence: req.SchemaRef},
		RemandInstructions: req.RemandInstructions,
		EventTime:          req.EventTime,
	}
	result, err := appeals.RecordDecision(
		cfg, h.deps.ContentStore, h.deps.KeyStore, h.deps.DelKeyStore,
		h.deps.Extractor, h.deps.Fetcher, h.deps.LeafReader, h.deps.Resolver,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := struct {
		buildResponse
		OpinionArtifactCID   string `json:"opinion_artifact_cid,omitempty"`
		OpinionContentDigest string `json:"opinion_content_digest,omitempty"`
	}{}
	signing := envelope.SigningPayload(result.DecisionEntry)
	resp.SigningPayload = base64Encode(signing)
	resp.EntryBytes = base64Encode(signing)
	resp.Header = &result.DecisionEntry.Header
	if result.OpinionArtifact != nil {
		resp.OpinionArtifactCID = result.OpinionArtifact.ArtifactCID.String()
		resp.OpinionContentDigest = result.OpinionArtifact.ContentDigest.String()
	}
	writeJSON(w, http.StatusOK, resp)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/appeals/mandates/affirm
// ─────────────────────────────────────────────────────────────────────

type appealMandateAffirmRequest struct {
	Destination          string  `json:"destination"`
	LowerCourtCaseLogDID string  `json:"lower_court_case_log_did"`
	LowerCourtCaseSeq    uint64  `json:"lower_court_case_seq"`
	LowerCourtScopeLogDID string `json:"lower_court_scope_log_did"`
	LowerCourtScopeSeq    uint64 `json:"lower_court_scope_seq"`
	PriorAuthority       *logPositionRef `json:"prior_authority,omitempty"`
	AppellateDecisionLogDID string `json:"appellate_decision_log_did"`
	AppellateDecisionSeq    uint64 `json:"appellate_decision_seq"`
	SchemaRef    *uint64 `json:"schema_ref,omitempty"`
	SchemaLogDID string  `json:"schema_log_did,omitempty"`
	EventTime    int64   `json:"event_time,omitempty"`
}

type appealMandateAffirmHandler struct{ deps *Dependencies }

func (h *appealMandateAffirmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	var req appealMandateAffirmRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" {
		writeError(w, http.StatusBadRequest, "destination required")
		return
	}
	cfg := appeals.MandateConfig{
		Destination:        req.Destination,
		SignerDID:          signer,
		LowerCourtCasePos:  types.LogPosition{LogDID: req.LowerCourtCaseLogDID, Sequence: req.LowerCourtCaseSeq},
		LowerCourtScopePos: types.LogPosition{LogDID: req.LowerCourtScopeLogDID, Sequence: req.LowerCourtScopeSeq},
		AppellateDecisionPos: types.LogPosition{
			LogDID: req.AppellateDecisionLogDID, Sequence: req.AppellateDecisionSeq,
		},
		Outcome:   "affirm",
		EventTime: req.EventTime,
	}
	if req.PriorAuthority != nil {
		pa := req.PriorAuthority.toLogPosition()
		cfg.PriorAuthority = &pa
	}
	if req.SchemaRef != nil && req.SchemaLogDID != "" {
		cfg.SchemaRef = &types.LogPosition{LogDID: req.SchemaLogDID, Sequence: *req.SchemaRef}
	}
	entry, err := appeals.IssueMandateAffirm(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeBuildResponse(w, entry)
}
