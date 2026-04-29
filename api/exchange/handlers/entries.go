/*
FILE PATH: exchange/handlers/entries.go

DESCRIPTION:
    Entry lifecycle handlers: build → sign → submit. The exchange
    holds the private key, builds entries via SDK builders, signs
    with the custodied key, and forwards to the operator.

    Five endpoints:
      POST /v1/entries/build             → SDK Build* → unsigned entry bytes
      POST /v1/entries/sign              → sign with custodied key
      POST /v1/entries/submit            → forward signed bytes to operator
      POST /v1/entries/build-sign-submit → all three in one call
      GET  /v1/entries/status/{hash}     → submission tracking

KEY DEPENDENCIES:
    - ortholog-sdk/builder: all Build* functions (guide §11.3)
    - exchange/keystore: Sign (key custody)
    - exchange/auth: SignerDIDFromContext (authenticated caller)
*/
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/api/exchange/auth"
	"github.com/clearcompass-ai/judicial-network/api/exchange/index"
	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
)

// Dependencies shared across all exchange handlers.
type Dependencies struct {
	OperatorEndpoint      string
	ArtifactStoreEndpoint string
	VerificationEndpoint  string
	KeyStore              keystore.KeyStore
	Index                 *index.LogIndex
	ExchangeDID           string
}

// ─── Build ──────────────────────────────────────────────────────────

type EntryBuildHandler struct{ deps *Dependencies }

func NewEntryBuildHandler(deps *Dependencies) *EntryBuildHandler {
	return &EntryBuildHandler{deps: deps}
}

type BuildRequest struct {
	Destination string
	Builder       string          `json:"builder"`
	SignerDID     string          `json:"signer_did"`
	DomainPayload json.RawMessage `json:"domain_payload"`
	TargetRoot    *uint64         `json:"target_root,omitempty"`
	LogDID        string          `json:"log_did,omitempty"`
}

func (h *EntryBuildHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callerDID := auth.SignerDIDFromContext(r.Context())

	var req BuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.SignerDID == "" {
		req.SignerDID = callerDID
	}

	entry, err := dispatchBuilder(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// SDK v7.75 forbids Serialize on unsigned entries. The build
	// endpoint returns SigningPayload — the exact bytes the caller
	// (or the exchange's key custody) must hash and sign before the
	// envelope can be re-assembled and submitted.
	entryBytes := envelope.SigningPayload(entry)

	writeJSON(w, http.StatusOK, map[string]any{
		"entry_bytes": entryBytes,
	})
}

func dispatchBuilder(req BuildRequest) (*envelope.Entry, error) {
	switch req.Builder {
	case "root_entity":
		return builder.BuildRootEntity(builder.RootEntityParams{
			Destination: req.Destination,
			SignerDID: req.SignerDID,
			Payload:   req.DomainPayload,
		})
	case "amendment":
		var targetRoot types.LogPosition
		if req.TargetRoot != nil {
			targetRoot = types.LogPosition{LogDID: req.LogDID, Sequence: *req.TargetRoot}
		}
		return builder.BuildAmendment(builder.AmendmentParams{
			Destination: req.Destination,
			SignerDID:  req.SignerDID,
			TargetRoot: targetRoot,
			Payload:    req.DomainPayload,
		})
	case "commentary":
		return builder.BuildCommentary(builder.CommentaryParams{
			Destination: req.Destination,
			SignerDID: req.SignerDID,
			Payload:   req.DomainPayload,
		})
	case "enforcement":
		return builder.BuildEnforcement(builder.EnforcementParams{
			Destination: req.Destination,
			SignerDID: req.SignerDID,
			Payload:   req.DomainPayload,
		})
	default:
		return nil, fmt.Errorf("unknown builder: %s", req.Builder)
	}
}

// ─── Sign ───────────────────────────────────────────────────────────

type EntrySignHandler struct{ deps *Dependencies }

func NewEntrySignHandler(deps *Dependencies) *EntrySignHandler {
	return &EntrySignHandler{deps: deps}
}

type SignRequest struct {
	EntryBytes []byte `json:"entry_bytes"`
	SignerDID  string `json:"signer_did"`
}

func (h *EntrySignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	sig, err := h.deps.KeyStore.Sign(req.SignerDID, req.EntryBytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"signed_entry_bytes": append(req.EntryBytes, sig...),
		"signature":          sig,
	})
}

// ─── Submit ─────────────────────────────────────────────────────────

type EntrySubmitHandler struct{ deps *Dependencies }

func NewEntrySubmitHandler(deps *Dependencies) *EntrySubmitHandler {
	return &EntrySubmitHandler{deps: deps}
}

func (h *EntrySubmitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body failed")
		return
	}

	// Forward to operator.
	resp, err := http.Post(
		h.deps.OperatorEndpoint+"/v1/entries",
		"application/octet-stream",
		bytes.NewReader(body),
	)
	if err != nil {
		writeError(w, http.StatusBadGateway, "operator unreachable")
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// ─── Build+Sign+Submit ──────────────────────────────────────────────

type EntryFullHandler struct{ deps *Dependencies }

func NewEntryFullHandler(deps *Dependencies) *EntryFullHandler {
	return &EntryFullHandler{deps: deps}
}

func (h *EntryFullHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callerDID := auth.SignerDIDFromContext(r.Context())

	var req BuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.SignerDID == "" {
		req.SignerDID = callerDID
	}

	// Build.
	entry, err := dispatchBuilder(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// v7.75 split: signers sign over SigningPayload (preamble +
	// header + payload) — never over a Serialize that already
	// includes a signatures section. After signing, re-build the
	// entry with the signature attached and Serialize the result
	// for transport to the operator.
	signingPayload := envelope.SigningPayload(entry)
	sig, err := h.deps.KeyStore.Sign(req.SignerDID, signingPayload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing failed")
		return
	}
	signedEntry, err := envelope.NewEntry(entry.Header, entry.DomainPayload, []envelope.Signature{
		{
			SignerDID: entry.Header.SignerDID,
			AlgoID:    envelope.SigAlgoECDSA,
			Bytes:     sig,
		},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "assemble signed entry: "+err.Error())
		return
	}
	signed := envelope.Serialize(signedEntry)

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

// ─── Status ─────────────────────────────────────────────────────────

type EntryStatusHandler struct{ deps *Dependencies }

func NewEntryStatusHandler(deps *Dependencies) *EntryStatusHandler {
	return &EntryStatusHandler{deps: deps}
}

func (h *EntryStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	// In production, track submission status in a local DB.
	writeJSON(w, http.StatusOK, map[string]any{
		"hash":   hash,
		"status": "submitted",
	})
}

// ─── Helpers ────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
