/*
FILE PATH: api/judicial/parties_sealed.go

DESCRIPTION:
    Sealed party binding handler. Daily reality: minor cases, victim
    protection, witness anonymity. The real party DID is encrypted via
    PRE; only an opaque vendor DID appears on the parties log.
    Authorized officers decrypt via GrantArtifactAccess sealed mode.

    Wire shape carries every cfg field from parties.SealedBindingConfig
    plus the artifact-stack deps already on Dependencies.

      POST /v1/judicial/parties/bindings/sealed → CreateSealedBinding

    Returns the binding entry's signing payload PLUS the published
    encrypted-mapping artifact's CID (the caller can audit which CID
    holds the sealed identity record).
*/
package judicial

import (
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/parties"
)

type partyBindingSealedRequest struct {
	Destination  string `json:"destination"`
	VendorDID    string `json:"vendor_did"`
	RealDID      string `json:"real_did"`
	CaseRef      string `json:"case_ref"`
	CaseDID      string `json:"case_did,omitempty"`
	CaseSeq      uint64 `json:"case_seq,omitempty"`
	Role         string `json:"role"`
	OwnerDID     string `json:"owner_did"`
	SchemaRef    uint64 `json:"schema_ref"`
	SchemaLogDID string `json:"schema_log_did"`
	EventTime    int64  `json:"event_time,omitempty"`
}

type partyBindingSealedHandler struct{ deps *Dependencies }

func (h *partyBindingSealedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	var req partyBindingSealedRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" || req.VendorDID == "" || req.RealDID == "" {
		writeError(w, http.StatusBadRequest,
			"destination, vendor_did, and real_did required")
		return
	}
	cfg := parties.SealedBindingConfig{
		Destination: req.Destination,
		SignerDID:   signer,
		VendorDID:   req.VendorDID,
		RealDID:     req.RealDID,
		CaseRef:     req.CaseRef,
		CaseDID:     req.CaseDID,
		CaseSeq:     req.CaseSeq,
		Role:        req.Role,
		OwnerDID:    req.OwnerDID,
		SchemaRef:   types.LogPosition{LogDID: req.SchemaLogDID, Sequence: req.SchemaRef},
		EventTime:   req.EventTime,
	}
	result, err := parties.CreateSealedBinding(
		cfg, h.deps.ContentStore, h.deps.KeyStore, h.deps.DelKeyStore,
		h.deps.Extractor, h.deps.Fetcher, h.deps.Resolver,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := struct {
		buildResponse
		EncryptedMappingCID   string `json:"encrypted_mapping_cid,omitempty"`
		EncryptedContentDigest string `json:"encrypted_content_digest,omitempty"`
	}{}
	writeBuildResponseTo(&resp.buildResponse, result.Entry)
	if result.EncryptedMapping != nil {
		resp.EncryptedMappingCID = result.EncryptedMapping.ArtifactCID.String()
		resp.EncryptedContentDigest = result.EncryptedMapping.ContentDigest.String()
	}
	writeJSON(w, http.StatusOK, resp)
}
