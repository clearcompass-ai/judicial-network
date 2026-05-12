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

	v0.3.0: both handlers read the per-source-log witness topology
	from deps.WitnessSets (a single map[string]*cosign.WitnessKeySet),
	not from three parallel maps. Keys + K + NetworkID + BLS verifier
	are bound together at construction time; the request supplies only
	source_log_did and the proof itself.
*/
package judicial

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"

	"github.com/clearcompass-ai/judicial-network/topology"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/verification/appeal-chain
// ─────────────────────────────────────────────────────────────────────

// Request payload carries the pre-walked AppealStep slice; this
// handler runs the cryptographic verification using deps.WitnessSets
// (the source of truth for per-log K, keys, and NetworkID).
type verifyAppealChainRequest struct {
	Steps json.RawMessage `json:"steps"` // []verification.AppealStep — opaque to keep package clean
}

type verifyAppealChainHandler struct{ deps *Dependencies }

func (h *verifyAppealChainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.Context()
	if requireCaller(w, r) == "" {
		return
	}
	if len(h.deps.WitnessSets) == 0 {
		writeError(w, http.StatusInternalServerError,
			"WitnessSets must be configured for appeal-chain verification")
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
	verified, err := verification.VerifyAppealChain(steps, h.deps.WitnessSets)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, verified)
}

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/verification/cross-log-proof
// ─────────────────────────────────────────────────────────────────────

// crossLogProofRequest accepts a serialized SDK CrossLogProof + the
// source-log DID. The handler looks up the source log's witness
// topology via deps.WitnessSets — one lookup, no three-way drift
// possible. The legacy override fields (source_witness_keys_b64,
// source_witness_quorum, source_network_id_hex) are removed in
// v0.3.0; per-request overrides would defeat the encapsulation
// guarantee.
type crossLogProofRequest struct {
	Proof                  json.RawMessage `json:"proof"`
	SourceLogDID           string          `json:"source_log_did"`
	AnchorPayloadExtractor string          `json:"anchor_payload_extractor,omitempty"`
}

type verifyCrossLogProofHandler struct{ deps *Dependencies }

func (h *verifyCrossLogProofHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.Context()
	if requireCaller(w, r) == "" {
		return
	}
	var req crossLogProofRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Proof) == 0 || req.SourceLogDID == "" {
		writeError(w, http.StatusBadRequest, "proof and source_log_did required")
		return
	}
	var proof types.CrossLogProof
	if err := json.Unmarshal(req.Proof, &proof); err != nil {
		writeError(w, http.StatusBadRequest, "proof must be a valid CrossLogProof JSON")
		return
	}
	set, ok := h.deps.WitnessSets[req.SourceLogDID]
	if !ok || set == nil {
		writeError(w, http.StatusBadRequest,
			"no witness set for source_log_did (pre-configure via WitnessSets at boot)")
		return
	}
	// Only the relay-attestation extractor is supported; the topology
	// package owns the canonical JSON layout. Future extractor
	// registries would route by AnchorPayloadExtractor here.
	if req.AnchorPayloadExtractor != "" && req.AnchorPayloadExtractor != "relay_attestation" {
		writeError(w, http.StatusBadRequest,
			"anchor_payload_extractor: only \"relay_attestation\" supported")
		return
	}
	verifyErr := verifier.VerifyCrossLogProof(proof, set, topology.ExtractAnchorPayload)
	if verifyErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"verified": false,
			"error":    verifyErr.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verified": true})
}

// decodeWitnessKeys is retained for ergonomic test-side construction
// of in-memory WitnessKeySets from base64-encoded BLS pubkeys.
// Production wiring builds WitnessSets at boot from operational
// config; the request path no longer accepts inline keys.
func decodeWitnessKeys(b64Keys []string) ([]types.WitnessPublicKey, error) {
	out := make([]types.WitnessPublicKey, 0, len(b64Keys))
	for _, s := range b64Keys {
		raw, err := decodeBase64(s)
		if err != nil {
			return nil, errors.New("witness_keys_b64 entry not valid base64")
		}
		out = append(out, types.WitnessPublicKey{PublicKey: raw})
	}
	return out, nil
}
