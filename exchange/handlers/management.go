/*
FILE PATH: exchange/handlers/management.go

DESCRIPTION:
    Management handlers: delegations, keys, identity, and scope
    governance. Each wraps SDK primitives with key custody.

    Delegation:  POST /v1/delegations, DELETE /v1/delegations/{did}
    Keys:        POST /v1/keys/generate, POST /v1/keys/rotate,
                 POST /v1/keys/escrow, GET /v1/keys
    Identity:    POST /v1/dids, GET /v1/dids
    Scope:       POST /v1/scope/propose, POST /v1/scope/approve/{pos},
                 POST /v1/scope/execute/{pos}

KEY DEPENDENCIES:
    - ortholog-sdk/builder: BuildDelegation, BuildRevocation,
      BuildKeyRotation, BuildKeyPrecommit (guide §11.3)
    - ortholog-sdk/did: GenerateDIDKey, CreateDIDDocument (guide §17)
    - ortholog-sdk/lifecycle: ProposeAmendment, BuildApprovalCosignature,
      ExecuteAmendment, ExecuteRemoval (guide §20.2)
    - ortholog-sdk/crypto/escrow: SplitGF256, EncryptForNode (guide §15)
    - exchange/keystore: key custody
*/
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"

	"github.com/clearcompass-ai/judicial-network/exchange/auth"
)

// ─── Delegation Create ──────────────────────────────────────────────

type DelegationCreateHandler struct{ deps *Dependencies }

func NewDelegationCreateHandler(deps *Dependencies) *DelegationCreateHandler {
	return &DelegationCreateHandler{deps: deps}
}

type DelegationRequest struct {
	DelegatorDID  string          `json:"delegator_did"`
	DelegateDID   string          `json:"delegate_did"`
	DomainPayload json.RawMessage `json:"domain_payload"`
}

func (h *DelegationCreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callerDID := auth.SignerDIDFromContext(r.Context())

	var req DelegationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.DelegatorDID == "" {
		req.DelegatorDID = callerDID
	}

	result, err := builder.BuildDelegation(builder.DelegationParams{
		SignerDID:     req.DelegatorDID,
		DelegateDID:   req.DelegateDID,
		DomainPayload: req.DomainPayload,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	sig, err := h.deps.KeyStore.Sign(req.DelegatorDID, result.EntryBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing failed")
		return
	}

	signed := append(result.EntryBytes, sig...)
	submitToOperator(w, h.deps.OperatorEndpoint, signed)
}

// ─── Delegation Revoke ──────────────────────────────────────────────

type DelegationRevokeHandler struct{ deps *Dependencies }

func NewDelegationRevokeHandler(deps *Dependencies) *DelegationRevokeHandler {
	return &DelegationRevokeHandler{deps: deps}
}

func (h *DelegationRevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callerDID := auth.SignerDIDFromContext(r.Context())
	targetDID := r.PathValue("did")

	var body struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	payload, _ := json.Marshal(map[string]any{
		"revocation_reason": body.Reason,
		"target_did":        targetDID,
	})

	result, err := builder.BuildRevocation(builder.RevocationParams{
		SignerDID:     callerDID,
		TargetDID:     targetDID,
		DomainPayload: payload,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	sig, err := h.deps.KeyStore.Sign(callerDID, result.EntryBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing failed")
		return
	}

	signed := append(result.EntryBytes, sig...)
	submitToOperator(w, h.deps.OperatorEndpoint, signed)
}

// ─── Key Generate ───────────────────────────────────────────────────

type KeyGenerateHandler struct{ deps *Dependencies }

func NewKeyGenerateHandler(deps *Dependencies) *KeyGenerateHandler {
	return &KeyGenerateHandler{deps: deps}
}

func (h *KeyGenerateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DID     string `json:"did"`
		Purpose string `json:"purpose"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	info, err := h.deps.KeyStore.Generate(req.DID, req.Purpose)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, info)
}

// ─── Key Rotate ─────────────────────────────────────────────────────

type KeyRotateHandler struct{ deps *Dependencies }

func NewKeyRotateHandler(deps *Dependencies) *KeyRotateHandler {
	return &KeyRotateHandler{deps: deps}
}

func (h *KeyRotateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callerDID := auth.SignerDIDFromContext(r.Context())

	var req struct {
		DID          string `json:"did"`
		RotationTier int    `json:"rotation_tier"` // 1, 2, or 3
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.DID == "" {
		req.DID = callerDID
	}

	// Rotate key in keystore.
	newInfo, err := h.deps.KeyStore.Rotate(req.DID, req.RotationTier)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Build + sign + submit key rotation entry.
	payload, _ := json.Marshal(map[string]any{
		"rotation_tier": req.RotationTier,
		"key_id":        newInfo.KeyID,
	})

	rotEntry, err := builder.BuildKeyRotation(builder.KeyRotationParams{
		SignerDID:     req.DID,
		NewPublicKey:  newInfo.PublicKey,
		DomainPayload: payload,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rotation entry build failed")
		return
	}

	sig, err := h.deps.KeyStore.Sign(req.DID, rotEntry.EntryBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing failed")
		return
	}

	signed := append(rotEntry.EntryBytes, sig...)
	submitToOperator(w, h.deps.OperatorEndpoint, signed)
}

// ─── Key Escrow ─────────────────────────────────────────────────────

type KeyEscrowHandler struct{ deps *Dependencies }

func NewKeyEscrowHandler(deps *Dependencies) *KeyEscrowHandler {
	return &KeyEscrowHandler{deps: deps}
}

func (h *KeyEscrowHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DID       string              `json:"did"`
		Nodes     []escrow.NodeConfig `json:"nodes"`
		Threshold int                 `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	// Export private key for splitting.
	privKey, err := h.deps.KeyStore.ExportForEscrow(req.DID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Split via Shamir.
	shares, err := escrow.SplitGF256(privKey, len(req.Nodes), req.Threshold)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "shamir split failed")
		return
	}

	// Encrypt each share for its target node via ECIES.
	var encryptedShares [][]byte
	for i, node := range req.Nodes {
		encrypted, err := escrow.EncryptForNode(shares[i], node)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "ecies encrypt failed")
			return
		}
		encryptedShares = append(encryptedShares, encrypted)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"did":              req.DID,
		"threshold":        req.Threshold,
		"total_shares":     len(encryptedShares),
		"encrypted_shares": encryptedShares,
	})
}

// ─── Key List ───────────────────────────────────────────────────────

type KeyListHandler struct{ deps *Dependencies }

func NewKeyListHandler(deps *Dependencies) *KeyListHandler {
	return &KeyListHandler{deps: deps}
}

func (h *KeyListHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	keys := h.deps.KeyStore.List()
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// ─── DID Create ─────────────────────────────────────────────────────

type DIDCreateHandler struct{ deps *Dependencies }

func NewDIDCreateHandler(deps *Dependencies) *DIDCreateHandler {
	return &DIDCreateHandler{deps: deps}
}

func (h *DIDCreateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string `json:"method"` // "web"
		Domain string `json:"domain"` // "courts.nashville.gov"
		Path   string `json:"path"`   // "criminal" or "role:judge-mcclendon-2026"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	didStr, doc, err := did.CreateDIDDocument(did.CreateParams{
		Method: req.Method,
		Domain: req.Domain,
		Path:   req.Path,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Generate and store key for this DID.
	keyInfo, err := h.deps.KeyStore.Generate(didStr, "signing")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"did":          didStr,
		"document":     doc,
		"public_key":   keyInfo.PublicKey,
		"key_id":       keyInfo.KeyID,
	})
}

// ─── DID List ───────────────────────────────────────────────────────

type DIDListHandler struct{ deps *Dependencies }

func NewDIDListHandler(deps *Dependencies) *DIDListHandler {
	return &DIDListHandler{deps: deps}
}

func (h *DIDListHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	keys := h.deps.KeyStore.List()
	dids := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		dids = append(dids, map[string]any{
			"did":      k.DID,
			"key_id":   k.KeyID,
			"purpose":  k.Purpose,
			"created":  k.Created,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"dids": dids})
}

// ─── Scope Propose ──────────────────────────────────────────────────

type ScopeProposeHandler struct{ deps *Dependencies }

func NewScopeProposeHandler(deps *Dependencies) *ScopeProposeHandler {
	return &ScopeProposeHandler{deps: deps}
}

func (h *ScopeProposeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callerDID := auth.SignerDIDFromContext(r.Context())

	var req struct {
		ProposalType string          `json:"proposal_type"` // "add_authority", "remove_authority", etc.
		TargetDID    string          `json:"target_did"`
		Description  string          `json:"description"`
		Payload      json.RawMessage `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	proposalType := lifecycle.ProposalTypeFromString(req.ProposalType)

	proposal, err := lifecycle.ProposeAmendment(lifecycle.AmendmentProposalParams{
		ProposerDID:     callerDID,
		ProposalType:    proposalType,
		TargetDID:       req.TargetDID,
		Description:     req.Description,
		ProposalPayload: req.Payload,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	sig, err := h.deps.KeyStore.Sign(callerDID, proposal.EntryBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing failed")
		return
	}

	signed := append(proposal.EntryBytes, sig...)
	submitToOperator(w, h.deps.OperatorEndpoint, signed)
}

// ─── Scope Approve ──────────────────────────────────────────────────

type ScopeApproveHandler struct{ deps *Dependencies }

func NewScopeApproveHandler(deps *Dependencies) *ScopeApproveHandler {
	return &ScopeApproveHandler{deps: deps}
}

func (h *ScopeApproveHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callerDID := auth.SignerDIDFromContext(r.Context())
	posStr := r.PathValue("pos")
	pos, err := strconv.ParseUint(posStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid position")
		return
	}

	approval, err := lifecycle.BuildApprovalCosignature(lifecycle.ApprovalParams{
		ApproverDID:  callerDID,
		ProposalPos:  pos,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	sig, err := h.deps.KeyStore.Sign(callerDID, approval.EntryBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing failed")
		return
	}

	signed := append(approval.EntryBytes, sig...)
	submitToOperator(w, h.deps.OperatorEndpoint, signed)
}

// ─── Scope Execute ──────────────────────────────────────────────────

type ScopeExecuteHandler struct{ deps *Dependencies }

func NewScopeExecuteHandler(deps *Dependencies) *ScopeExecuteHandler {
	return &ScopeExecuteHandler{deps: deps}
}

func (h *ScopeExecuteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callerDID := auth.SignerDIDFromContext(r.Context())
	posStr := r.PathValue("pos")
	pos, err := strconv.ParseUint(posStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid position")
		return
	}

	execution, err := lifecycle.ExecuteAmendment(lifecycle.AmendmentExecutionParams{
		ExecutorDID: callerDID,
		ProposalPos: pos,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	sig, err := h.deps.KeyStore.Sign(callerDID, execution.EntryBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing failed")
		return
	}

	signed := append(execution.EntryBytes, sig...)
	submitToOperator(w, h.deps.OperatorEndpoint, signed)
}

// ─── Shared ─────────────────────────────────────────────────────────

func submitToOperator(w http.ResponseWriter, endpoint string, signed []byte) {
	resp, err := http.Post(
		endpoint+"/v1/entries",
		"application/octet-stream",
		bytes.NewReader(signed),
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, "operator unreachable")
		return
	}
	defer resp.Body.Close()

	var opResp map[string]any
	json.NewDecoder(resp.Body).Decode(&opResp)
	writeJSON(w, resp.StatusCode, opResp)
}
