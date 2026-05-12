/*
FILE PATH: api/judicial/artifacts.go

DESCRIPTION:

	Artifact handlers — direct publish/retrieve/expunge/reencrypt of
	documents WITHOUT going through a case-binding wrapper. Daily
	reality of these flows:

	  POST /v1/judicial/artifacts                       → PublishArtifact
	  GET  /v1/judicial/artifacts/retrieve              → RetrieveArtifact
	  DELETE /v1/judicial/artifacts/{cid}               → ExpungeArtifact
	  POST /v1/judicial/artifacts/reencrypt             → ReencryptArtifact

	The case-bound flows (file a document INTO a case) live in
	cases_filings.go and call cases.File which wraps PublishArtifact.
	These handlers are for raw artifact-store operations: bulk
	document upload pre-case-creation, evidence-store retrievals
	against pre-existing CIDs, key-rotation re-encryption, etc.
*/
package judicial

import (
	"net/http"
	"time"

	"github.com/clearcompass-ai/attesta/storage"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/cases/artifact"
)

func registerArtifactRoutes(mux *http.ServeMux, deps *Dependencies) {
	mux.Handle("POST /v1/judicial/artifacts", &artifactPublishHandler{deps: deps})
	mux.Handle("GET /v1/judicial/artifacts/retrieve", &artifactRetrieveHandler{deps: deps})
	mux.Handle("DELETE /v1/judicial/artifacts/{cid}", &artifactExpungeHandler{deps: deps})
	mux.Handle("POST /v1/judicial/artifacts/reencrypt", &artifactReencryptHandler{deps: deps})
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/artifacts
// ─────────────────────────────────────────────────────────────────────

type artifactPublishRequest struct {
	PlaintextB64      string            `json:"plaintext_b64"`
	SchemaLogDID      string            `json:"schema_log_did"`
	SchemaSeq         uint64            `json:"schema_seq"`
	OwnerDID          string            `json:"owner_did"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	DisclosureScope   string            `json:"disclosure_scope,omitempty"`
	InitialRecipients []string          `json:"initial_recipients,omitempty"`
}

type artifactPublishHandler struct{ deps *Dependencies }

func (h *artifactPublishHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if requireCaller(w, r) == "" {
		return
	}
	var req artifactPublishRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	plaintext, err := decodeBase64(req.PlaintextB64)
	if err != nil || len(plaintext) == 0 {
		writeError(w, http.StatusBadRequest, "plaintext_b64 must be valid non-empty base64")
		return
	}
	cfg := artifact.PublishConfig{
		Plaintext:         plaintext,
		SchemaRef:         types.LogPosition{LogDID: req.SchemaLogDID, Sequence: req.SchemaSeq},
		OwnerDID:          req.OwnerDID,
		Metadata:          req.Metadata,
		DisclosureScope:   req.DisclosureScope,
		InitialRecipients: req.InitialRecipients,
	}
	pub, err := artifact.PublishArtifact(ctx,
		cfg, h.deps.ContentStore, h.deps.KeyStore, h.deps.DelKeyStore,
		h.deps.Extractor, h.deps.Fetcher, h.deps.Resolver)

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := struct {
		ArtifactCID   string            `json:"artifact_cid"`
		ContentDigest string            `json:"content_digest"`
		Scheme        string            `json:"scheme"`
		Metadata      map[string]string `json:"metadata,omitempty"`
		PkDelB64      string            `json:"pk_del_b64,omitempty"`
	}{
		ArtifactCID:   pub.ArtifactCID.String(),
		ContentDigest: pub.ContentDigest.String(),
		Scheme:        pub.Scheme,
		Metadata:      pub.Metadata,
	}
	resp.PkDelB64 = pub.PkDel // already-encoded string per artifact.PublishedArtifact
	writeJSON(w, http.StatusOK, resp)
}

// ─────────────────────────────────────────────────────────────────────
// GET /v1/judicial/artifacts/retrieve?destination=...&artifact_cid=...
// ─────────────────────────────────────────────────────────────────────

// Retrieve returns a SDK GrantResult (envelope.GrantResult) which the
// caller's wallet uses to decrypt the ciphertext. The handler does
// NOT decrypt server-side — the caller's recipient private key holds
// the unwrap key.
type artifactRetrieveHandler struct{ deps *Dependencies }

func (h *artifactRetrieveHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requesterDID := requireCaller(w, r)
	if requesterDID == "" {
		return
	}
	q := r.URL.Query()
	dest := q.Get("destination")
	cidStr := q.Get("artifact_cid")
	if dest == "" || cidStr == "" {
		writeError(w, http.StatusBadRequest, "destination and artifact_cid required")
		return
	}
	artCID, err := storage.ParseCID(cidStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid artifact_cid")
		return
	}
	digestStr := q.Get("content_digest")
	digestCID, _ := storage.ParseCID(digestStr) // optional
	caseRootSeq, _ := parseUint64(q.Get("case_root_seq"))
	scopeSeq, _ := parseUint64(q.Get("scope_seq"))
	filingSeq, _ := parseUint64(q.Get("filing_seq"))
	schemaSeq, _ := parseUint64(q.Get("schema_seq"))
	expirySec, _ := parseUint64(q.Get("expiry_seconds"))

	req := artifact.RetrievalRequest{
		Destination:     dest,
		ArtifactCID:     artCID,
		ContentDigest:   digestCID,
		FilingEntryPos:  types.LogPosition{LogDID: q.Get("filing_log_did"), Sequence: filingSeq},
		CaseRootPos:     types.LogPosition{LogDID: q.Get("case_root_log_did"), Sequence: caseRootSeq},
		ScopePos:        types.LogPosition{LogDID: q.Get("scope_log_did"), Sequence: scopeSeq},
		RequesterDID:    requesterDID,
		GranterDID:      q.Get("granter_did"),
		SchemaRef:       types.LogPosition{LogDID: q.Get("schema_log_did"), Sequence: schemaSeq},
		RetrievalExpiry: time.Duration(expirySec) * time.Second,
	}
	grant, err := artifact.RetrieveArtifact(ctx,
		req, h.deps.KeyStore, h.deps.DelKeyStore, nil,
		h.deps.Extractor, h.deps.LeafReader, h.deps.Fetcher, h.deps.Resolver)

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, grant)
}

// parseUint64 is a small fmt.Sscan wrapper that returns zero on
// parse failure — used for optional query params where empty == 0.
func parseUint64(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	var v uint64
	_, err := sscanU64(s, &v)
	return v, err
}
