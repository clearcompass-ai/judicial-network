package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/escrow"
	"github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/lifecycle"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"

	"github.com/clearcompass-ai/judicial-network/api/exchange/auth"

	"github.com/dustinxie/ecc"
)

// parseSecp256k1PubKey parses a 65-byte uncompressed secp256k1 public key.
func parseSecp256k1PubKey(data []byte) (*ecdsa.PublicKey, error) {
	c := ecc.P256k1()
	x, y := elliptic.Unmarshal(c, data)
	if x == nil {
		return nil, fmt.Errorf("invalid secp256k1 public key (%d bytes)", len(data))
	}
	return &ecdsa.PublicKey{Curve: c, X: x, Y: y}, nil
}

// ─── Delegation Create ──────────────────────────────────────────────

type DelegationCreateHandler struct{ deps *Dependencies }

func NewDelegationCreateHandler(deps *Dependencies) *DelegationCreateHandler {
	return &DelegationCreateHandler{deps: deps}
}

type DelegationRequest struct {
	Destination   string          `json:"destination"`
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
	if req.Destination == "" {
		writeError(w, http.StatusBadRequest, "destination required")
		return
	}
	if req.DelegatorDID == "" {
		req.DelegatorDID = callerDID
	}

	entry, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: req.Destination,
		SignerDID:   req.DelegatorDID,
		DelegateDID: req.DelegateDID,
		Payload:     req.DomainPayload,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	signAndSubmit(w, h.deps, req.DelegatorDID, entry)
}

// ─── Delegation Revoke ──────────────────────────────────────────────

type DelegationRevokeHandler struct{ deps *Dependencies }

func NewDelegationRevokeHandler(deps *Dependencies) *DelegationRevokeHandler {
	return &DelegationRevokeHandler{deps: deps}
}

func (h *DelegationRevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callerDID := auth.SignerDIDFromContext(r.Context())
	_ = r.PathValue("did") // targetDID for logging/audit

	var body struct {
		Destination string `json:"destination"`
		Reason      string `json:"reason"`
		TargetPos   uint64 `json:"target_pos"` // log position of the delegation to revoke
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if body.Destination == "" {
		writeError(w, http.StatusBadRequest, "destination required")
		return
	}

	payload, _ := json.Marshal(map[string]any{
		"revocation_reason": body.Reason,
	})

	entry, err := builder.BuildRevocation(builder.RevocationParams{
		Destination: body.Destination,
		SignerDID:   callerDID,
		TargetRoot:  types.LogPosition{Sequence: body.TargetPos},
		Payload:     payload,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	signAndSubmit(w, h.deps, callerDID, entry)
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
		Destination  string `json:"destination"`
		DID          string `json:"did"`
		RotationTier int    `json:"rotation_tier"`
		TargetPos    uint64 `json:"target_pos"` // DID profile entity position
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Destination == "" {
		writeError(w, http.StatusBadRequest, "destination required")
		return
	}
	if req.DID == "" {
		req.DID = callerDID
	}

	// Stage the next key as PENDING — the current (retiring) key stays
	// active + signable so it can authorize this rotation (old-key-signs).
	staged, err := h.deps.KeyStore.StageNextKey(req.DID, req.RotationTier)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Canonical entry_signer_rotation_v1 payload naming the NEW key, so the
	// ledger admits it (admission/rotation_entry_verifier) and a consumer's
	// RotationHistorySource can project + chain-verify it.
	payload, err := verifier.EncodeRotationPayload(verifier.RotationPayload{
		SignerDID:    req.DID,
		NewPublicKey: staged.PublicKey,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rotation payload: "+err.Error())
		return
	}

	entry, err := builder.BuildKeyRotation(builder.KeyRotationParams{
		Destination: req.Destination,
		SignerDID:   req.DID,
		TargetRoot:  types.LogPosition{Sequence: req.TargetPos},
		Payload:     payload,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rotation entry build failed")
		return
	}

	// Sign with the OLD (still-active) key + embed; submit; promote the new
	// key ONLY after the rotation entry is accepted on-log (else the local
	// active key would diverge from the log's position-authoritative one).
	digest := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := h.deps.KeyStore.SignEntry(req.DID, digest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rotation signing failed")
		return
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: req.DID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	signed, err := envelope.Serialize(entry)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "serialize entry: "+err.Error())
		return
	}

	cap := newCapturingResponseWriter()
	submitToLedgerProtected(cap, h.deps, signed)
	if cap.status >= 200 && cap.status < 300 {
		if _, err := h.deps.KeyStore.CommitRotation(req.DID); err != nil {
			writeError(w, http.StatusInternalServerError,
				"rotation accepted on-log but keystore promote failed: "+err.Error())
			return
		}
	}
	cap.replayTo(w)
}

// ─── Key Escrow ─────────────────────────────────────────────────────

type KeyEscrowHandler struct{ deps *Dependencies }

func NewKeyEscrowHandler(deps *Dependencies) *KeyEscrowHandler {
	return &KeyEscrowHandler{deps: deps}
}

func (h *KeyEscrowHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DID         string   `json:"did"`
		NodePubKeys []string `json:"node_pub_keys"` // hex-encoded 65-byte secp256k1
		Threshold   int      `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	privKey, err := h.deps.KeyStore.ExportForEscrow(req.DID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	shares, err := escrow.SplitGF256(privKey, req.Threshold, len(req.NodePubKeys))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "shamir split failed")
		return
	}

	var encryptedShares [][]byte
	for i, hexKey := range req.NodePubKeys {
		pubKeyBytes, err := hex.DecodeString(hexKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid node public key hex")
			return
		}
		pubKey, err := parseSecp256k1PubKey(pubKeyBytes)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid secp256k1 public key")
			return
		}
		shareValue := shares[i].Value
		encrypted, err := escrow.EncryptForNode(shareValue[:], pubKey)
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
		Domain string `json:"domain"`
		Path   string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	didStr := did.NewWebDID(req.Domain, req.Path)

	keyInfo, err := h.deps.KeyStore.Generate(didStr, "signing")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"did":        didStr,
		"public_key": keyInfo.PublicKey,
		"key_id":     keyInfo.KeyID,
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
			"did":     k.DID,
			"key_id":  k.KeyID,
			"purpose": k.Purpose,
			"created": k.Created,
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
		ProposalType string          `json:"proposal_type"`
		TargetDID    string          `json:"target_did"`
		Description  string          `json:"description"`
		Payload      json.RawMessage `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	proposal, err := lifecycle.ProposeAmendment(lifecycle.AmendmentProposalParams{
		ProposerDID:     callerDID,
		ProposalType:    proposalTypeFromString(req.ProposalType),
		TargetDID:       req.TargetDID,
		Description:     req.Description,
		ProposalPayload: req.Payload,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// ProposeAmendment returns *AmendmentProposal with .Entry field.
	signAndSubmit(w, h.deps, callerDID, proposal.Entry)
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

	var body struct {
		Destination string `json:"destination"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if body.Destination == "" {
		writeError(w, http.StatusBadRequest, "destination required")
		return
	}

	// BuildApprovalCosignature takes 3 args: signerDID, proposalPos, eventTime.
	entry, err := lifecycle.BuildApprovalCosignature(
		callerDID, body.Destination,
		types.LogPosition{Sequence: pos},
		time.Now().UTC().UnixMicro(),
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	signAndSubmit(w, h.deps, callerDID, entry)
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

	var req struct {
		NewAuthoritySet   map[string]struct{} `json:"new_authority_set"`
		ApprovalPositions []uint64            `json:"approval_positions"`
		PriorAuthority    *uint64             `json:"prior_authority,omitempty"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	approvals := make([]types.LogPosition, len(req.ApprovalPositions))
	for i, p := range req.ApprovalPositions {
		approvals[i] = types.LogPosition{Sequence: p}
	}

	var prior *types.LogPosition
	if req.PriorAuthority != nil {
		p := types.LogPosition{Sequence: *req.PriorAuthority}
		prior = &p
	}

	entry, err := lifecycle.ExecuteAmendment(lifecycle.ExecuteAmendmentParams{
		ExecutorDID:       callerDID,
		ScopePos:          types.LogPosition{Sequence: pos},
		NewAuthoritySet:   req.NewAuthoritySet,
		ApprovalPositions: approvals,
		PriorAuthority:    prior,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	signAndSubmit(w, h.deps, callerDID, entry)
}

// ─── Shared ─────────────────────────────────────────────────────────

// signAndSubmit signs an entry with the signer's custodied secp256k1 key
// and forwards it to the ledger. The signature is EMBEDDED in the
// envelope's Signatures section (sig over sha256(SigningPayload), the
// digest attestation.VerifyEntrySignatures checks), then the fully
// hydrated entry is serialized — never the raw-sig-appended shape the
// SDK deserializer would reject.
func signAndSubmit(w http.ResponseWriter, deps *Dependencies, signerDID string, entry *envelope.Entry) {
	digest := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := deps.KeyStore.SignEntry(signerDID, digest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing failed")
		return
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: signerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	signed, err := envelope.Serialize(entry)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "serialize entry: "+err.Error())
		return
	}
	submitToLedgerProtected(w, deps, signed)
}

// proposalTypeFromString maps a string label to the SDK's ProposalType enum.
// The SDK provides ProposalType.String() (enum→string) but not the reverse.
func proposalTypeFromString(s string) lifecycle.ProposalType {
	switch s {
	case "add_authority":
		return lifecycle.ProposalAddAuthority
	case "remove_authority":
		return lifecycle.ProposalRemoveAuthority
	case "change_parameters":
		return lifecycle.ProposalChangeParameters
	default:
		return lifecycle.ProposalDomainExtension
	}
}

// ledgerSubmitClient is package-level so all 4 submit-to-ledger
// sites share the SDK's tuned transport: MaxIdleConnsPerHost=100
// (vs stdlib 2) plus the RetryAfterRoundTripper that honors the
// ledger's WAL-pressure 503 + Retry-After responses transparently.
// One client, one conn pool, one retry policy — no behavior drift
// across the 4 sites.
//
//	ships api/middleware/reliability.NewTunedClient as a
//
// MaxConnsPerHost-capped alternative (256 idle / 1024 max). Wiring
// it here requires composing it with sdklog.RetryAfterRoundTripper
// so ledger-backpressure handling is preserved; deferred until
// the SDK exposes the round-tripper as a RoundTripper-compatible
// wrapper around an arbitrary inner Transport.
var ledgerSubmitClient = sdklog.DefaultClient(30 * time.Second)

// submitToLedger posts signed canonical wire bytes to the
// ledger's /v1/entries endpoint via the SDK-tuned client. Every
// submit-to-ledger site in api/exchange/handlers routes through
// here so the wire shape, retry policy, and timeout are owned in
// one place.
func submitToLedger(w http.ResponseWriter, endpoint string, signed []byte) {
	resp, err := ledgerSubmitClient.Post(
		endpoint+"/v1/entries",
		"application/octet-stream",
		bytes.NewReader(signed),
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, "ledger unreachable")
		return
	}
	defer resp.Body.Close()

	var opResp map[string]any
	json.NewDecoder(resp.Body).Decode(&opResp)
	writeJSON(w, resp.StatusCode, opResp)
}
