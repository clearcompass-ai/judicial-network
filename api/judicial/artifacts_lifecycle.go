/*
FILE PATH: api/judicial/artifacts_lifecycle.go

DESCRIPTION:
    Artifact lifecycle handlers: expungement (cryptographic erasure
    of a single CID's keys + ciphertext) and re-encryption (key
    rotation against an existing CID).

      DELETE /v1/judicial/artifacts/{cid}
      POST   /v1/judicial/artifacts/reencrypt

    Daily reality:
      - Expunge is the per-CID counterpart to enforcement.ExpungeCase
        (which expunges every CID under a case in one shot). Used
        for record-correction or per-document expungement orders.
      - Re-encryption is invoked by the operator on a key rotation
        cycle to replace AES-GCM keys; ciphertext is re-encrypted
        with a fresh key and the old key is destroyed.
*/
package judicial

import (
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/storage"

	"github.com/clearcompass-ai/judicial-network/cases/artifact"
)

// ─────────────────────────────────────────────────────────────────────
// DELETE /v1/judicial/artifacts/{cid}
// ─────────────────────────────────────────────────────────────────────

type artifactExpungeHandler struct{ deps *Dependencies }

func (h *artifactExpungeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	cidStr := r.PathValue("cid")
	if cidStr == "" {
		writeError(w, http.StatusBadRequest, "cid required")
		return
	}
	cid, err := storage.ParseCID(cidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid cid")
		return
	}
	verifyBefore := r.URL.Query().Get("verify") == "true"

	cfg := artifact.ExpungeConfig{
		ArtifactCID:        cid,
		VerifyBeforeDelete: verifyBefore,
	}
	result, err := artifact.ExpungeArtifact(
		cfg, h.deps.KeyStore, h.deps.DelKeyStore, h.deps.ContentStore,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := struct {
		AESKeyDestroyed        bool   `json:"aes_key_destroyed"`
		DelegationKeyDestroyed bool   `json:"delegation_key_destroyed"`
		ContentDeleted         bool   `json:"content_deleted"`
		ContentDeleteError     string `json:"content_delete_error,omitempty"`
	}{
		AESKeyDestroyed:        result.AESKeyDestroyed,
		DelegationKeyDestroyed: result.DelegationKeyDestroyed,
		ContentDeleted:         result.ContentDeleted,
	}
	if result.ContentDeleteError != nil {
		resp.ContentDeleteError = result.ContentDeleteError.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/artifacts/reencrypt
// ─────────────────────────────────────────────────────────────────────

type artifactReencryptRequest struct {
	OldCID              string `json:"old_cid"`
	DeleteOldCiphertext bool   `json:"delete_old_ciphertext"`
}

type artifactReencryptHandler struct{ deps *Dependencies }

func (h *artifactReencryptHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	var req artifactReencryptRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.OldCID == "" {
		writeError(w, http.StatusBadRequest, "old_cid required")
		return
	}
	cid, err := storage.ParseCID(req.OldCID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid old_cid")
		return
	}
	cfg := artifact.ReencryptConfig{
		OldCID:              cid,
		DeleteOldCiphertext: req.DeleteOldCiphertext,
	}
	result, err := artifact.ReencryptArtifact(
		cfg, h.deps.KeyStore, h.deps.ContentStore,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := struct {
		OldCID                 string `json:"old_cid"`
		NewCID                 string `json:"new_cid"`
		ContentDigestUnchanged bool   `json:"content_digest_unchanged"`
	}{
		OldCID:                 result.OldCID.String(),
		NewCID:                 result.NewCID.String(),
		ContentDigestUnchanged: result.ContentDigestUnchanged,
	}
	writeJSON(w, http.StatusOK, resp)
}
