/*
FILE PATH: exchange/handlers/artifacts.go

DESCRIPTION:
    Artifact lifecycle handlers. The exchange encrypts plaintext
    locally, computes CID, pushes ciphertext to the artifact store,
    and returns metadata for the caller to embed in entry Domain Payload.

    POST /v1/artifacts/publish     → encrypt + push → { cid, digest, key }
    POST /v1/artifacts/{cid}/grant → build + sign + submit grant entry

KEY DEPENDENCIES:
    - ortholog-sdk/crypto/artifact: Encrypt (guide §14)
    - ortholog-sdk/storage: ComputeCID (guide §8.1)
    - ortholog-sdk/crypto: SHA256 (guide §12)
    - ortholog-sdk/lifecycle: GrantArtifactAccess, CheckGrantAuthorization
      (guide §20.4)
*/
package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/storage"

	"github.com/clearcompass-ai/judicial-network/api/exchange/auth"
)

// ─── Publish ────────────────────────────────────────────────────────

type ArtifactPublishHandler struct{ deps *Dependencies }

func NewArtifactPublishHandler(deps *Dependencies) *ArtifactPublishHandler {
	return &ArtifactPublishHandler{deps: deps}
}

func (h *ArtifactPublishHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = auth.SignerDIDFromContext(r.Context())

	// Read plaintext from request body.
	plaintext, err := io.ReadAll(io.LimitReader(r.Body, 64<<20)) // 64MB max
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body failed")
		return
	}

	// Encrypt — SDK generates key internally.
	ciphertext, artKey, err := artifact.EncryptArtifact(plaintext)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	// Compute CID of ciphertext.
	cid := storage.Compute(ciphertext)

	// Compute content digest of plaintext.
	digest := sha256.Sum256(plaintext)

	// Push ciphertext to artifact store.
	pushReq, err := http.NewRequest("POST",
		h.deps.ArtifactStoreEndpoint+"/v1/artifacts",
		bytes.NewReader(ciphertext))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "push request failed")
		return
	}
	pushReq.Header.Set("X-Artifact-CID", cid.String())
	pushReq.Header.Set("Content-Type", "application/octet-stream")

	pushResp, err := http.DefaultClient.Do(pushReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "artifact store unreachable")
		return
	}
	defer pushResp.Body.Close()

	if pushResp.StatusCode != http.StatusOK && pushResp.StatusCode != http.StatusCreated {
		writeError(w, pushResp.StatusCode, "artifact store push failed")
		return
	}

	// Return metadata. Caller embeds cid + digest in entry Domain Payload.
	writeJSON(w, http.StatusOK, map[string]any{
		"cid":            cid.String(),
		"content_digest": hex.EncodeToString(digest[:]),
		"encryption_key": base64.StdEncoding.EncodeToString(artKey.Key[:]),
		"encryption":     "AES-256-GCM",
	})
}

// ─── Grant ──────────────────────────────────────────────────────────

type ArtifactGrantHandler struct{ deps *Dependencies }

func NewArtifactGrantHandler(deps *Dependencies) *ArtifactGrantHandler {
	return &ArtifactGrantHandler{deps: deps}
}

type GrantRequest struct {
	GranterDID  string `json:"granter_did"`
	GranteeDID  string `json:"grantee_did"`
	ArtifactKey string `json:"artifact_key"` // base64-encoded AES key
	SchemaRef   string `json:"schema_ref"`
}

func (h *ArtifactGrantHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callerDID := auth.SignerDIDFromContext(r.Context())
	cid := r.PathValue("cid")

	var req GrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.GranterDID == "" {
		req.GranterDID = callerDID
	}

	// Build grant entry via SDK.
	grantPayload, _ := json.Marshal(map[string]any{
		"artifact_cid":   cid,
		"granter_did":    req.GranterDID,
		"grantee_did":    req.GranteeDID,
		"decryption_key": req.ArtifactKey,
		"schema_ref":     req.SchemaRef,
	})

	// Build as commentary entry carrying the grant.
	buildReq := BuildRequest{
		Builder:       "commentary",
		SignerDID:     req.GranterDID,
		DomainPayload: grantPayload,
	}

	entry, err := dispatchBuilder(buildReq)
	if err != nil {
		writeError(w, http.StatusBadRequest, "grant build failed")
		return
	}

	entryBytes := envelope.Serialize(entry)

	// Sign with granter's custodied key.
	sig, err := h.deps.KeyStore.Sign(req.GranterDID, entryBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "grant signing failed")
		return
	}

	signed := append(entryBytes, sig...)

	// Submit to operator.
	resp, err := http.Post(
		h.deps.OperatorEndpoint+"/v1/entries",
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
