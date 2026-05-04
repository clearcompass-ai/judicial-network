/*
FILE PATH: api/judicial/verification_appeals.go

DESCRIPTION:
    Appellate-history + cross-log proof verification handlers.

      POST /v1/judicial/verification/appeal-chain    → VerifyAppealChain
      POST /v1/judicial/verification/cross-log-proof → verifier.VerifyCrossLogProof

    Walking the chain end-to-end is also stubbed because WalkAppealChain
    needs a NextProofFn — a Go callback that fetches the next hop's
    proof from a log; not directly mappable to one HTTP call. Production
    callers walk hop-by-hop using cross-log-proof verification.
*/
package judicial

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"

	"github.com/clearcompass-ai/judicial-network/verification"
)

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/verification/appeal-chain
// ─────────────────────────────────────────────────────────────────────

// Request payload carries the pre-walked AppealStep slice; this
// handler runs the cryptographic verification (witness signatures,
// inclusion proofs) using the WitnessKeys + Quorum + BLSVerifier
// already on Dependencies.
type verifyAppealChainRequest struct {
	Steps json.RawMessage `json:"steps"` // []verification.AppealStep — opaque to keep package clean
}

type verifyAppealChainHandler struct{ deps *Dependencies }

func (h *verifyAppealChainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	if h.deps.BLSVerifier == nil || h.deps.WitnessKeys == nil || h.deps.WitnessQuorum == nil {
		writeError(w, http.StatusInternalServerError,
			"BLSVerifier, WitnessKeys, and WitnessQuorum must be configured")
		return
	}
	var req verifyAppealChainRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var steps []verification.AppealStep
	if err := json.Unmarshal(req.Steps, &steps); err != nil {
		writeError(w, http.StatusBadRequest, "steps must be a valid AppealStep array")
		return
	}
	if len(steps) == 0 {
		writeError(w, http.StatusBadRequest, "steps required")
		return
	}
	verified, err := verification.VerifyAppealChain(
		steps, h.deps.WitnessKeys, h.deps.WitnessQuorum,
		h.deps.NetworkID, h.deps.BLSVerifier,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, verified)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/verification/cross-log-proof
// ─────────────────────────────────────────────────────────────────────

// crossLogProofRequest accepts a serialized SDK CrossLogProof + an
// expected source-entry hash + the witness key set for the SOURCE
// log (the proof's anchor side is verified against keys/quorum the
// caller MUST supply since cross-log proofs span trust boundaries).
type crossLogProofRequest struct {
	Proof json.RawMessage `json:"proof"`

	// SourceWitnessKeys + SourceWitnessQuorum override the
	// Dependencies.WitnessKeys / Quorum maps for THIS verification
	// call. Reason: source log lives in a different trust boundary
	// than the caller's; the caller MUST tell the API which key
	// set to verify the source tree-head signatures against.
	SourceLogDID           string   `json:"source_log_did"`
	SourceWitnessKeysB64   []string `json:"source_witness_keys_b64,omitempty"`
	SourceWitnessQuorum    int      `json:"source_witness_quorum,omitempty"`
	AnchorPayloadExtractor string   `json:"anchor_payload_extractor,omitempty"`
}

type verifyCrossLogProofHandler struct{ deps *Dependencies }

func (h *verifyCrossLogProofHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	if h.deps.BLSVerifier == nil {
		writeError(w, http.StatusInternalServerError, "BLSVerifier must be configured")
		return
	}
	var req crossLogProofRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Proof) == 0 || req.SourceLogDID == "" {
		writeError(w, http.StatusBadRequest,
			"proof and source_log_did required")
		return
	}
	var proof types.CrossLogProof
	if err := json.Unmarshal(req.Proof, &proof); err != nil {
		writeError(w, http.StatusBadRequest, "proof must be a valid CrossLogProof JSON")
		return
	}

	keys, err := decodeWitnessKeys(req.SourceWitnessKeysB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(keys) == 0 {
		// Fall back to Dependencies map keyed by source log DID.
		keys = h.deps.WitnessKeys[req.SourceLogDID]
	}
	quorum := req.SourceWitnessQuorum
	if quorum == 0 {
		quorum = h.deps.WitnessQuorum[req.SourceLogDID]
	}
	if len(keys) == 0 || quorum == 0 {
		writeError(w, http.StatusBadRequest,
			"source_witness_keys + quorum required (or pre-configured for the source log)")
		return
	}

	// The verifier needs an "anchor payload extractor" — a function
	// that pulls a tree-head reference out of the anchor entry's
	// payload. Phase 7 doesn't ship a registry of such extractors;
	// callers MAY supply one named in the request (future C6 work)
	// or fall back to the SDK's default for relay attestations.
	if req.AnchorPayloadExtractor != "" && req.AnchorPayloadExtractor != "relay_attestation" {
		writeError(w, http.StatusBadRequest,
			"anchor_payload_extractor: only \"relay_attestation\" supported in Phase 7")
		return
	}
	anchorExt := defaultAnchorExtractor

	verifyErr := verifier.VerifyCrossLogProof(
		proof, keys, quorum, h.deps.NetworkID, h.deps.BLSVerifier, anchorExt,
	)
	if verifyErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"verified": false,
			"error":    verifyErr.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verified": true})
}

// defaultAnchorExtractor pulls the anchor tree-head reference from a
// relay attestation payload via the SDK's ExtractAnchorPayload-shaped
// API. Phase 7 only supports relay-attestation anchor entries.
var defaultAnchorExtractor = func(payload []byte) ([32]byte, error) {
	// SDK exposes this on the topology side; we wrap to keep import
	// surface minimal here.
	if len(payload) < 32 {
		var zero [32]byte
		return zero, errors.New("anchor payload too short to extract tree-head ref")
	}
	var head [32]byte
	copy(head[:], payload[:32])
	return head, nil
}

// decodeWitnessKeys converts base64-encoded BLS pubkeys to the SDK
// types.WitnessPublicKey shape. Returns an error if any entry fails
// to decode.
func decodeWitnessKeys(b64Keys []string) ([]types.WitnessPublicKey, error) {
	out := make([]types.WitnessPublicKey, 0, len(b64Keys))
	for _, s := range b64Keys {
		raw, err := decodeBase64(s)
		if err != nil {
			return nil, errors.New("source_witness_keys_b64 entry not valid base64")
		}
		out = append(out, types.WitnessPublicKey{PublicKey: raw})
	}
	return out, nil
}
