/*
FILE PATH: api/judicial/cases_filings.go

DESCRIPTION:

	The artifact-bearing cases.* handlers: filings (every motion,
	sworn document, evidence) and judicial actions (rulings, orders,
	sentences, dispositions when accompanied by a written opinion).

	Both flows share the same artifact-stack dependencies on the
	Dependencies struct (ContentStore + KeyStore + DelegationKeyStore
	+ Extractor + Fetcher + Resolver). Co-locating them keeps the
	file's responsibility tight: "all cases.* handlers that touch
	the artifact pipeline."

	Daily reality:
	  - Filings are the highest-volume write path.
	  - Judicial actions optionally carry a written opinion as a
	    Plaintext attachment which is encrypted on the way through.
*/
package judicial

import (
	"net/http"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/cases"
)

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/cases/{caseRootSeq}/filings
// ─────────────────────────────────────────────────────────────────────

type caseFilingRequest struct {
	Destination           string           `json:"destination"`
	CaseRootLogDID        string           `json:"case_root_log_did"`
	SchemaRef             uint64           `json:"schema_ref"`
	SchemaLogDID          string           `json:"schema_log_did"`
	DelegationPointers    []logPositionRef `json:"delegation_pointers,omitempty"`
	DocumentType          string           `json:"document_type"`
	DocumentTitle         string           `json:"document_title"`
	PlaintextB64          string           `json:"plaintext_b64"`
	OwnerDID              string           `json:"owner_did"`
	DisclosureScope       string           `json:"disclosure_scope"`
	InitialRecipients     []string         `json:"initial_recipients,omitempty"`
	ExtraPayload          map[string]any   `json:"extra_payload,omitempty"`
	EventTime             int64            `json:"event_time,omitempty"`
	AttestationPolicyName *string          `json:"attestation_policy_name,omitempty"`
}

type caseFilingHandler struct{ deps *Dependencies }

func (h *caseFilingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	var req caseFilingRequest
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
	plaintext, err := decodeBase64(req.PlaintextB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "plaintext_b64 must be valid base64")
		return
	}
	cfg := cases.FilingConfig{
		Destination:           req.Destination,
		SignerDID:             signer,
		CaseRootPos:           types.LogPosition{LogDID: req.CaseRootLogDID, Sequence: caseRootSeq},
		SchemaRef:             types.LogPosition{LogDID: req.SchemaLogDID, Sequence: req.SchemaRef},
		DelegationPointers:    toLogPositions(req.DelegationPointers),
		EventTime:             req.EventTime,
		DocumentType:          req.DocumentType,
		DocumentTitle:         req.DocumentTitle,
		Plaintext:             plaintext,
		OwnerDID:              req.OwnerDID,
		DisclosureScope:       req.DisclosureScope,
		InitialRecipients:     req.InitialRecipients,
		ExtraPayload:          req.ExtraPayload,
		AttestationPolicyName: req.AttestationPolicyName,
	}
	result, err := cases.File(ctx,
		cfg, h.deps.ContentStore, h.deps.KeyStore, h.deps.DelKeyStore,
		h.deps.Extractor, h.deps.Fetcher, h.deps.Resolver)

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := struct {
		buildResponse
		ArtifactCID   string `json:"artifact_cid"`
		ContentDigest string `json:"content_digest"`
	}{
		ArtifactCID:   result.Published.ArtifactCID.String(),
		ContentDigest: result.Published.ContentDigest.String(),
	}
	signing := envelope.SigningPayload(result.Entry)
	resp.SigningPayload = base64Encode(signing)
	resp.EntryBytes = base64Encode(signing)
	resp.Header = &result.Entry.Header
	writeJSON(w, http.StatusOK, resp)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/cases/{caseRootSeq}/actions
// ─────────────────────────────────────────────────────────────────────

type caseActionRequest struct {
	Destination           string           `json:"destination"`
	CaseRootLogDID        string           `json:"case_root_log_did"`
	ActionType            string           `json:"action_type"` // ruling | order | sentence | disposition
	Description           string           `json:"description"`
	SchemaRef             uint64           `json:"schema_ref"`
	SchemaLogDID          string           `json:"schema_log_did"`
	CandidatePositions    []logPositionRef `json:"candidate_positions,omitempty"`
	PlaintextB64          string           `json:"plaintext_b64,omitempty"`
	DisclosureScope       string           `json:"disclosure_scope,omitempty"`
	InitialRecipients     []string         `json:"initial_recipients,omitempty"`
	ExtraPayload          map[string]any   `json:"extra_payload,omitempty"`
	EventTime             int64            `json:"event_time,omitempty"`
	AttestationPolicyName *string          `json:"attestation_policy_name,omitempty"`
}

type caseActionHandler struct{ deps *Dependencies }

func (h *caseActionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	judge := requireCaller(w, r)
	if judge == "" {
		return
	}
	var req caseActionRequest
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
	plaintext, err := decodeBase64(req.PlaintextB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "plaintext_b64 must be valid base64")
		return
	}
	cfg := cases.JudicialActionConfig{
		Destination:           req.Destination,
		JudgeDID:              judge,
		CaseRootPos:           types.LogPosition{LogDID: req.CaseRootLogDID, Sequence: caseRootSeq},
		ActionType:            req.ActionType,
		Description:           req.Description,
		SchemaRef:             types.LogPosition{LogDID: req.SchemaLogDID, Sequence: req.SchemaRef},
		CandidatePositions:    toLogPositions(req.CandidatePositions),
		Plaintext:             plaintext,
		DisclosureScope:       req.DisclosureScope,
		InitialRecipients:     req.InitialRecipients,
		ExtraPayload:          req.ExtraPayload,
		EventTime:             req.EventTime,
		AttestationPolicyName: req.AttestationPolicyName,
	}
	result, err := cases.RecordJudicialAction(ctx,
		cfg, h.deps.ContentStore, h.deps.KeyStore, h.deps.DelKeyStore,
		h.deps.Extractor, h.deps.Fetcher, h.deps.LeafReader, h.deps.Resolver)

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := struct {
		buildResponse
		ArtifactCID   string `json:"artifact_cid,omitempty"`
		ContentDigest string `json:"content_digest,omitempty"`
	}{}
	signing := envelope.SigningPayload(result.Entry)
	resp.SigningPayload = base64Encode(signing)
	resp.EntryBytes = base64Encode(signing)
	resp.Header = &result.Entry.Header
	if result.Published != nil {
		resp.ArtifactCID = result.Published.ArtifactCID.String()
		resp.ContentDigest = result.Published.ContentDigest.String()
	}
	writeJSON(w, http.StatusOK, resp)
}
