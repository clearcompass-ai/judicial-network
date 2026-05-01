/*
FILE PATH: api/judicial/cases.go

DESCRIPTION:
    HTTP handlers wrapping the cases.* domain functions. These are the
    daily-clerk-activity routes: file a new case, file documents into
    an existing case, record a judge's action (ruling, order, sentence,
    disposition), amend a case (status change / reassignment / artifact
    update), look up by docket number, and transfer to a different
    division or county.

    Daily-reality wire model:

      POST /v1/judicial/cases                          → InitiateCase
      POST /v1/judicial/cases/{docket}/filings         → File
      POST /v1/judicial/cases/{docket}/actions         → RecordJudicialAction
      POST /v1/judicial/cases/{docket}/amend           → AmendCase
      GET  /v1/judicial/cases/{docket}                 → LookupDocket
      POST /v1/judicial/cases/{docket}/transfer/division → TransferDivision
      POST /v1/judicial/cases/{docket}/transfer/county   → TransferCounty

    All POST routes return the buildResponse envelope (see server.go
    for the wire shape): signing_payload + entry_bytes + header. The
    caller signs and submits via /v1/entries/submit on api/exchange.

    The two most complex routes:

      POST .../filings         delegates to cases.File which builds
                               the case-amendment, encrypts the
                               document, pushes ciphertext to the
                               artifact store, returns
                               {entry, artifact_cid, content_digest}.
                               Caller signs the entry; the artifact
                               bytes are already on the store
                               regardless of submission outcome.

      POST .../transfer/county delegates to cases.TransferCounty
                               which builds a CrossLogProof, the
                               source amendment, and N delegation
                               mirrors for the target county log.
                               Returns ALL of those for the caller
                               to sign + submit (different signers
                               on different logs).
*/
package judicial

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/cases"
)

// ─────────────────────────────────────────────────────────────────────
// Route registration
// ─────────────────────────────────────────────────────────────────────

// registerCaseRoutes installs every cases.* handler on mux. Called by
// BuildHandler in server.go. Routes are scoped under /v1/judicial/
// (the composer mounts the whole tree under that prefix).
func registerCaseRoutes(mux *http.ServeMux, deps *Dependencies) {
	mux.Handle("POST /v1/judicial/cases", &caseInitiateHandler{deps: deps})
	mux.Handle("POST /v1/judicial/cases/{caseRootSeq}/filings", &caseFilingHandler{deps: deps})
	mux.Handle("POST /v1/judicial/cases/{caseRootSeq}/actions", &caseActionHandler{deps: deps})
	mux.Handle("POST /v1/judicial/cases/{caseRootSeq}/amend", &caseAmendHandler{deps: deps})
	mux.Handle("GET /v1/judicial/cases/{docket}", &caseLookupHandler{deps: deps})
	mux.Handle("POST /v1/judicial/cases/{caseRootSeq}/transfer/division", &caseTransferDivisionHandler{deps: deps})
	mux.Handle("POST /v1/judicial/cases/{caseRootSeq}/transfer/county", &caseTransferCountyHandler{deps: deps})
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/cases — case initiation (case_initiated event)
// ─────────────────────────────────────────────────────────────────────

// caseInitiateRequest is the wire shape POST /v1/judicial/cases accepts.
//
// Daily reality: a clerk receiving a new filing creates the case root
// entry first, then immediately files the initiating document (a
// complaint, an indictment, a petition) under the same case in a
// follow-up call. The two are separate to keep each entry's payload
// minimal and the cosignature mix appropriate per event_type.
type caseInitiateRequest struct {
	// Destination is the target exchange DID — required by every
	// build path. Defaulted to the caller's home destination by
	// the auth middleware in a future patch; for now MUST be
	// supplied explicitly.
	Destination string `json:"destination"`

	DocketNumber string `json:"docket_number"`
	CaseType     string `json:"case_type"` // criminal | civil | family | juvenile
	FiledDate    string `json:"filed_date"` // ISO 8601
	SchemaRef    *uint64 `json:"schema_ref,omitempty"`
	SchemaLogDID string  `json:"schema_log_did,omitempty"`

	// ExtraPayload carries case-class-specific fields (charges for
	// criminal, plaintiff/defendant for civil, etc.). Domain function
	// merges these into the entry's payload.
	ExtraPayload map[string]any `json:"extra_payload,omitempty"`

	EventTime int64 `json:"event_time,omitempty"`
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
		Destination:  req.Destination,
		SignerDID:    signer,
		DocketNumber: req.DocketNumber,
		CaseType:     req.CaseType,
		FiledDate:    req.FiledDate,
		ExtraPayload: req.ExtraPayload,
		EventTime:    req.EventTime,
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
// POST /v1/judicial/cases/{caseRootSeq}/filings — file a document
// ─────────────────────────────────────────────────────────────────────

// caseFilingRequest is the wire shape for filing a document into an
// existing case. The handler resolves caseRootSeq from the URL path
// and passes the rest through to cases.File.
//
// Daily reality: every motion, every sworn document, every piece of
// evidence becomes a filing. This is the highest-volume write path.
// Path A (no DelegationPointers) for self-signed amendments; Path B
// (DelegationPointers populated) for filings under a delegation chain
// (counsel filing on behalf of a party, etc.).
type caseFilingRequest struct {
	Destination     string  `json:"destination"`
	CaseRootLogDID  string  `json:"case_root_log_did"` // log holding the case root
	SchemaRef       uint64  `json:"schema_ref"`
	SchemaLogDID    string  `json:"schema_log_did"`

	// Delegation pointers turn this from Path A (same-signer
	// amendment) to Path B (delegated filing).
	DelegationPointers []logPositionRef `json:"delegation_pointers,omitempty"`

	DocumentType  string `json:"document_type"`  // motion | filing | evidence | ...
	DocumentTitle string `json:"document_title"`

	// Plaintext is the document bytes (base64). The handler hands
	// them to cases.File which encrypts + pushes to the artifact
	// store. NOT logged.
	PlaintextB64 string `json:"plaintext_b64"`

	OwnerDID          string   `json:"owner_did"`
	DisclosureScope   string   `json:"disclosure_scope"`
	InitialRecipients []string `json:"initial_recipients,omitempty"`
	ExtraPayload      map[string]any `json:"extra_payload,omitempty"`
	EventTime         int64    `json:"event_time,omitempty"`
}

// logPositionRef is the JSON wire shape for a types.LogPosition.
// Used everywhere a request needs to reference a specific log+seq.
type logPositionRef struct {
	LogDID   string `json:"log_did"`
	Sequence uint64 `json:"sequence"`
}

func (lp logPositionRef) toLogPosition() types.LogPosition {
	return types.LogPosition{LogDID: lp.LogDID, Sequence: lp.Sequence}
}

type caseFilingHandler struct{ deps *Dependencies }

func (h *caseFilingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	delegationPointers := make([]types.LogPosition, 0, len(req.DelegationPointers))
	for _, dp := range req.DelegationPointers {
		delegationPointers = append(delegationPointers, dp.toLogPosition())
	}

	cfg := cases.FilingConfig{
		Destination:        req.Destination,
		SignerDID:          signer,
		CaseRootPos:        types.LogPosition{LogDID: req.CaseRootLogDID, Sequence: caseRootSeq},
		SchemaRef:          types.LogPosition{LogDID: req.SchemaLogDID, Sequence: req.SchemaRef},
		DelegationPointers: delegationPointers,
		EventTime:          req.EventTime,
		DocumentType:       req.DocumentType,
		DocumentTitle:      req.DocumentTitle,
		Plaintext:          plaintext,
		OwnerDID:           req.OwnerDID,
		DisclosureScope:    req.DisclosureScope,
		InitialRecipients:  req.InitialRecipients,
		ExtraPayload:       req.ExtraPayload,
	}

	result, err := cases.File(
		cfg, h.deps.ContentStore, h.deps.KeyStore, h.deps.DelKeyStore,
		h.deps.Extractor, h.deps.Fetcher, h.deps.Resolver,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Filing returns the entry plus published-artifact metadata.
	// We bundle both into the response so the caller knows the
	// CID even before they sign+submit (the artifact is already
	// on the store).
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
// POST /v1/judicial/cases/{caseRootSeq}/actions — judicial action
// ─────────────────────────────────────────────────────────────────────

// Daily reality: every ruling, every order, every sentence, every
// disposition is a JudicialAction. The signer is the judge's DID
// (verified by the cosig mix policy at submit time). When the action
// produces a written opinion / order document, Plaintext carries it
// and the handler publishes via the artifact store on the way through.
type caseActionRequest struct {
	Destination    string `json:"destination"`
	CaseRootLogDID string `json:"case_root_log_did"`
	ActionType     string `json:"action_type"`  // ruling | order | sentence | disposition
	Description    string `json:"description"`
	SchemaRef      uint64 `json:"schema_ref"`
	SchemaLogDID   string `json:"schema_log_did"`

	CandidatePositions []logPositionRef `json:"candidate_positions,omitempty"`

	PlaintextB64      string         `json:"plaintext_b64,omitempty"`
	DisclosureScope   string         `json:"disclosure_scope,omitempty"`
	InitialRecipients []string       `json:"initial_recipients,omitempty"`
	ExtraPayload      map[string]any `json:"extra_payload,omitempty"`
	EventTime         int64          `json:"event_time,omitempty"`
}

type caseActionHandler struct{ deps *Dependencies }

func (h *caseActionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	candidates := make([]types.LogPosition, 0, len(req.CandidatePositions))
	for _, c := range req.CandidatePositions {
		candidates = append(candidates, c.toLogPosition())
	}

	cfg := cases.JudicialActionConfig{
		Destination:        req.Destination,
		JudgeDID:           judge,
		CaseRootPos:        types.LogPosition{LogDID: req.CaseRootLogDID, Sequence: caseRootSeq},
		ActionType:         req.ActionType,
		Description:        req.Description,
		SchemaRef:          types.LogPosition{LogDID: req.SchemaLogDID, Sequence: req.SchemaRef},
		CandidatePositions: candidates,
		Plaintext:          plaintext,
		DisclosureScope:    req.DisclosureScope,
		InitialRecipients:  req.InitialRecipients,
		ExtraPayload:       req.ExtraPayload,
		EventTime:          req.EventTime,
	}

	result, err := cases.RecordJudicialAction(
		cfg, h.deps.ContentStore, h.deps.KeyStore, h.deps.DelKeyStore,
		h.deps.Extractor, h.deps.Fetcher, h.deps.LeafReader, h.deps.Resolver,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Like filings, judicial actions may carry an artifact when
	// Plaintext was supplied. Bundle that metadata into the response.
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

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/cases/{caseRootSeq}/amend — case amendment
// ─────────────────────────────────────────────────────────────────────

// Daily reality: status changes (active → closed; sealed; reopened),
// reassignments to a different judge, and artifact-CID updates after
// re-encryption all flow through here. AmendmentType selects which
// branch of the payload schema applies.
type caseAmendRequest struct {
	Destination    string `json:"destination"`
	CaseRootLogDID string `json:"case_root_log_did"`

	AmendmentType  string `json:"amendment_type"` // status_change | reassignment | artifact_update
	NewStatus      string `json:"new_status,omitempty"`
	NewArtifactCID string `json:"new_artifact_cid,omitempty"`

	SchemaRef    *uint64 `json:"schema_ref,omitempty"`
	SchemaLogDID string  `json:"schema_log_did,omitempty"`

	EvidencePointers []logPositionRef `json:"evidence_pointers,omitempty"`
	ExtraPayload     map[string]any   `json:"extra_payload,omitempty"`
	EventTime        int64            `json:"event_time,omitempty"`
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

	evid := make([]types.LogPosition, 0, len(req.EvidencePointers))
	for _, e := range req.EvidencePointers {
		evid = append(evid, e.toLogPosition())
	}

	cfg := cases.AmendmentConfig{
		Destination:      req.Destination,
		SignerDID:        signer,
		CaseRootPos:      types.LogPosition{LogDID: req.CaseRootLogDID, Sequence: caseRootSeq},
		AmendmentType:    req.AmendmentType,
		NewStatus:        req.NewStatus,
		NewArtifactCID:   req.NewArtifactCID,
		EvidencePointers: evid,
		ExtraPayload:     req.ExtraPayload,
		EventTime:        req.EventTime,
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
// GET /v1/judicial/cases/{docket} — docket lookup
// ─────────────────────────────────────────────────────────────────────

// Read-side path: scan the cases log for an entry matching docket
// number (and the caller's signerDID for authorization). Daily reality:
// a clerk searches "Smith v. Jones 2026-CV-001" and gets the case
// root + state.
type caseLookupHandler struct{ deps *Dependencies }

func (h *caseLookupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	docket := r.PathValue("docket")
	if docket == "" {
		writeError(w, http.StatusBadRequest, "docket required")
		return
	}

	// LookupDocket needs a DocketScanner — production wires this to
	// an OperatorQueryAPI-backed scanner; tests stub. The Dependencies
	// struct does not currently expose the scanner directly because
	// scanner construction depends on which log to scan; for now,
	// callers SHOULD provide the cases log's query API in
	// Dependencies.LogQueries keyed by the entry's destination's
	// cases-log-DID. We resolve at request time.
	scanner, err := h.casesScannerFor(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	result, err := cases.LookupDocket(docket, signer, scanner, h.deps.Fetcher, h.deps.LeafReader)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// casesScannerFor looks up the caller's home cases-log scanner. For
// Phase 7 first commit, we expect the caller to supply the cases-log
// DID via the X-Cases-Log-DID header; production deployments may
// derive this from the auth context's home-court mapping in a later
// patch. Returning an error here means the configured Dependencies
// don't have the requested log's query API wired in.
func (h *caseLookupHandler) casesScannerFor(r *http.Request) (cases.DocketScanner, error) {
	logDID := r.Header.Get("X-Cases-Log-DID")
	if logDID == "" {
		return nil, fmt.Errorf("X-Cases-Log-DID header required")
	}
	q, ok := h.deps.LogQueries[logDID]
	if !ok {
		return nil, fmt.Errorf("no LogQueries entry for %s", logDID)
	}
	return docketScannerAdapter{api: q}, nil
}

// docketScannerAdapter adapts a sdklog.OperatorQueryAPI to the
// cases.DocketScanner interface (the domain function's narrow view —
// just QueryBySignerDID on top of the operator query API).
type docketScannerAdapter struct {
	api interface {
		QueryBySignerDID(did string) ([]types.EntryWithMetadata, error)
	}
}

func (a docketScannerAdapter) QueryBySignerDID(did string) ([]types.EntryWithMetadata, error) {
	return a.api.QueryBySignerDID(did)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/cases/{caseRootSeq}/transfer/division
// ─────────────────────────────────────────────────────────────────────

// Daily reality: cases move between divisions (criminal → family for
// inter-related matters; trial → mediation; etc.) within the same
// county. This is a single Path A amendment under the same court's
// jurisdiction.
type caseTransferDivisionRequest struct {
	Destination    string `json:"destination"`
	CaseRootLogDID string `json:"case_root_log_did"`
	TargetDivision string `json:"target_division"`
	Reason         string `json:"reason"`
	SchemaRef      *uint64 `json:"schema_ref,omitempty"`
	SchemaLogDID   string `json:"schema_log_did,omitempty"`
	EventTime      int64  `json:"event_time,omitempty"`
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
// POST /v1/judicial/cases/{caseRootSeq}/transfer/county — cross-log
// ─────────────────────────────────────────────────────────────────────

// Daily reality (rare but high-value): a Davidson County case moves
// to Williamson County (e.g., venue change). Three things happen:
//
//   1. CrossLogProof: cryptographic proof binding the source case to
//      the destination county's log.
//   2. Source amendment: marks the case "transferred" on Davidson's log.
//   3. Delegation mirrors: each of N delegations (judges, clerks)
//      authorized over the case gets a mirror entry on the target
//      county's log so target operator knows who can act.
//
// cases.TransferCounty's signature requires assembled CrossLogProof
// inputs (source/local Merkle provers, source/local cosigned tree
// heads, anchor refs, delegation querier). Composing those from raw
// HTTP inputs is its own subsystem; this handler is intentionally
// stubbed in commit C1 so the route is reserved without misleading
// callers about what it accepts. Wired in commit C5 alongside
// verification.* (which already speaks cross-log proofs) and the
// CrossLogProofBuilder helper in api/judicial/crosslog.go.
type caseTransferCountyHandler struct{ deps *Dependencies }

func (h *caseTransferCountyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"county transfer requires cross-log proof composition; wired in C5")
}

// ─────────────────────────────────────────────────────────────────────
// helpers used by case handlers (shared with future handler files)
// ─────────────────────────────────────────────────────────────────────

// pathSeq parses a uint64 path value. Returns false on parse failure
// so handlers can write a clean 400 message.
func pathSeq(r *http.Request, name string) (uint64, bool) {
	raw := r.PathValue(name)
	var v uint64
	_, err := fmt.Sscan(raw, &v)
	return v, err == nil
}

// decodeBase64 decodes a base64 string. Empty input returns nil + nil
// (the domain functions accept empty Plaintext when the action has no
// document attached).
func decodeBase64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// base64Encode is the inverse used in response building.
func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// buildPayloadFromEntry produces a buildResponse for any built entry.
func buildPayloadFromEntry(entry *envelope.Entry) buildResponse {
	signing := envelope.SigningPayload(entry)
	return buildResponse{
		SigningPayload: base64Encode(signing),
		EntryBytes:     base64Encode(signing),
		Header:         &entry.Header,
	}
}

