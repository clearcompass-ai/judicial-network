/*
FILE PATH: api/judicial/enforcement_audit.go

DESCRIPTION:

	The audit / compliance side of enforcement: expungement (full
	cryptographic erasure), sealed-evidence access grants, and
	compliance reports. These are lower-volume than sealing but more
	consequential.

	  POST /v1/judicial/enforcement/expunge          → ExpungeCase
	  POST /v1/judicial/enforcement/evidence-access  → GrantEvidenceAccess
	  GET  /v1/judicial/enforcement/compliance       → RunComplianceCheck

	Co-located here because they share the artifact-stack +
	authority-chain dependencies on the Dependencies struct.
*/
package judicial

import (
	"fmt"
	"net/http"
	"time"

	sdkartifact "github.com/clearcompass-ai/attesta/crypto/artifact"
	"github.com/clearcompass-ai/attesta/storage"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/enforcement"
)

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/enforcement/expunge
// ─────────────────────────────────────────────────────────────────────

// Daily reality (less frequent, irreversible): expungement
// CRYPTOGRAPHICALLY ERASES every artifact under the case. After
// submission the keystore deletes the per-artifact AES keys; the
// ciphertext on the artifact store becomes undecryptable forever.
type expungeRequest struct {
	Destination    string          `json:"destination"`
	CaseRootLogDID string          `json:"case_root_log_did"`
	CaseRootSeq    uint64          `json:"case_root_seq"`
	ScopeLogDID    string          `json:"scope_log_did"`
	ScopeSeq       uint64          `json:"scope_seq"`
	PriorAuthority *logPositionRef `json:"prior_authority,omitempty"`
	SchemaRef      *uint64         `json:"schema_ref,omitempty"`
	SchemaLogDID   string          `json:"schema_log_did,omitempty"`
	Authority      string          `json:"authority"`
	ArtifactCIDs   []string        `json:"artifact_cids"`
	EventTime      int64           `json:"event_time,omitempty"`
}

type expungeHandler struct{ deps *Dependencies }

func (h *expungeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	judge := requireCaller(w, r)
	if judge == "" {
		return
	}
	var req expungeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" {
		writeError(w, http.StatusBadRequest, "destination required")
		return
	}
	cids := make([]storage.CID, 0, len(req.ArtifactCIDs))
	for _, raw := range req.ArtifactCIDs {
		c, err := storage.ParseCID(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("invalid CID %q: %v", raw, err))
			return
		}
		cids = append(cids, c)
	}
	cfg := enforcement.ExpungementConfig{
		Destination:  req.Destination,
		JudgeDID:     judge,
		CaseRootPos:  types.LogPosition{LogDID: req.CaseRootLogDID, Sequence: req.CaseRootSeq},
		ScopePos:     types.LogPosition{LogDID: req.ScopeLogDID, Sequence: req.ScopeSeq},
		Authority:    req.Authority,
		ArtifactCIDs: cids,
		EventTime:    req.EventTime,
	}
	if req.PriorAuthority != nil {
		pa := req.PriorAuthority.toLogPosition()
		cfg.PriorAuthority = &pa
	}
	if req.SchemaRef != nil && req.SchemaLogDID != "" {
		cfg.SchemaRef = &types.LogPosition{LogDID: req.SchemaLogDID, Sequence: *req.SchemaRef}
	}
	result, err := enforcement.ExpungeCase(ctx,
		cfg, h.deps.KeyStore, h.deps.DelKeyStore, h.deps.ContentStore,
		h.deps.Fetcher, h.deps.LeafReader, h.deps.Extractor)

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := struct {
		buildResponse
		ExpungedCIDs     []string          `json:"expunged_cids,omitempty"`
		ComplianceReport map[string]string `json:"compliance_report,omitempty"`
	}{
		ExpungedCIDs:     []string{}, // populated below from result
		ComplianceReport: result.ComplianceReport,
	}
	writeBuildResponseTo(&resp.buildResponse, result.EnforcementEntry)
	for k := range result.ComplianceReport {
		resp.ExpungedCIDs = append(resp.ExpungedCIDs, k)
	}
	writeJSON(w, http.StatusOK, resp)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/enforcement/evidence-access
// ─────────────────────────────────────────────────────────────────────

// Daily reality: a sealed case has authorized recipients (defense
// counsel, prosecutor, court reporter). When one of those recipients
// requests access, this handler builds a SDK sealed-mode grant that
// the caller's wallet can decrypt under their key.
type evidenceAccessRequest struct {
	Destination        string         `json:"destination"`
	ArtifactCID        string         `json:"artifact_cid"`
	ContentDigest      string         `json:"content_digest"`
	FilingEntry        logPositionRef `json:"filing_entry"`
	CaseRoot           logPositionRef `json:"case_root"`
	Scope              logPositionRef `json:"scope"`
	RequesterDID       string         `json:"requester_did"`
	RequesterPubKeyB64 string         `json:"requester_pub_key_b64,omitempty"`
	GranterDID         string         `json:"granter_did"`
	SchemaRef          logPositionRef `json:"schema_ref"`
	OwnerMasterKeyB64  string         `json:"owner_master_key_b64,omitempty"`
	PkDelB64           string         `json:"pk_del_b64,omitempty"`
}

type evidenceAccessHandler struct{ deps *Dependencies }

func (h *evidenceAccessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if requireCaller(w, r) == "" {
		return
	}
	var req evidenceAccessRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" || req.ArtifactCID == "" {
		writeError(w, http.StatusBadRequest, "destination and artifact_cid required")
		return
	}
	artCID, err := storage.ParseCID(req.ArtifactCID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid artifact_cid")
		return
	}
	digestCID, err := storage.ParseCID(req.ContentDigest)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid content_digest")
		return
	}
	pubKey, err := decodeBase64(req.RequesterPubKeyB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "requester_pub_key_b64 must be base64")
		return
	}
	masterKey, err := decodeBase64(req.OwnerMasterKeyB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "owner_master_key_b64 must be base64")
		return
	}
	pkDel, err := decodeBase64(req.PkDelB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "pk_del_b64 must be base64")
		return
	}
	cfg := enforcement.EvidenceAccessConfig{
		Destination:     req.Destination,
		ArtifactCID:     artCID,
		ContentDigest:   digestCID,
		FilingEntryPos:  req.FilingEntry.toLogPosition(),
		CaseRootPos:     req.CaseRoot.toLogPosition(),
		ScopePos:        req.Scope.toLogPosition(),
		RequesterPubKey: pubKey,
		RequesterDID:    req.RequesterDID,
		GranterDID:      req.GranterDID,
		SchemaRef:       req.SchemaRef.toLogPosition(),
		OwnerMasterKey:  masterKey,
		PkDel:           pkDel,
	}
	// Sealed-mode grants don't actually need an SDK Capsule on the
	// path (PRE arrives later). Pass nil for now; future PRE wiring
	// adds the field to the request body.
	cfg.Capsule = (*sdkartifact.Capsule)(nil)
	grant, err := enforcement.GrantEvidenceAccess(ctx,
		cfg, h.deps.KeyStore, h.deps.DelKeyStore, nil,
		h.deps.Extractor, h.deps.LeafReader, h.deps.Fetcher, h.deps.Resolver)

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, grant)
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/judicial/enforcement/compliance?log_did=...&seq=...
// ─────────────────────────────────────────────────────────────────────

// Read-side: walks the authority chain rooted at the case to surface
// every active enforcement constraint (sealed, expunged, contested,
// override-pending). Daily reality: clerks running monthly compliance
// audits.
type complianceHandler struct{ deps *Dependencies }

func (h *complianceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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
	if _, err := sscanU64(seqStr, &seq); err != nil {
		writeError(w, http.StatusBadRequest, "seq must be a uint64")
		return
	}
	cfg := enforcement.ComplianceConfig{
		CaseRootPos:   types.LogPosition{LogDID: logDID, Sequence: seq},
		Now:           time.Now().UTC(),
		CheckContests: true,
	}
	report, err := enforcement.RunComplianceCheck(ctx,
		cfg, h.deps.Fetcher, h.deps.LeafReader, h.deps.Extractor)

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}
