/*
FILE PATH: api/judicial/verification_appeals.go

DESCRIPTION:

	Appellate-history + cross-log proof verification handlers.

	  POST /v1/judicial/verification/appeal-chain    → VerifyAppealChain
	  POST /v1/judicial/verification/cross-log-proof → crosslog.VerifyCrossLog

	Walking the chain end-to-end is also stubbed because WalkAppealChain
	needs a NextProofFn — a Go callback that fetches the next hop's
	proof from a log; not directly mappable to one HTTP call. Production
	callers walk hop-by-hop using cross-log-proof verification.

	v0.3.0: both handlers read the per-source-log witness topology
	from the deps' era resolver (FED-1 #107 — per-hop, head-anchored),
	not from three parallel maps. Keys + K + NetworkID + BLS verifier
	are bound together at construction time; the request supplies only
	source_log_did and the proof itself.
*/
package judicial

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"

	"github.com/clearcompass-ai/judicial-network/verification"
	jntrust "github.com/clearcompass-ai/judicial-network/verification/trust"

	"github.com/clearcompass-ai/judicial-network/verification/eras"
)

// ─────────────────────────────────────────────────────────────────────
// POST /v1/judicial/verification/appeal-chain
// ─────────────────────────────────────────────────────────────────────

// Request payload carries the pre-walked AppealStep slice; this
// handler runs the cryptographic verification using deps.Eras — every
// hop's witness set resolved ERA-CORRECTLY for that hop's own cosigned
// head (FED-1 #107: an appeal chain spans eras by construction).
type verifyAppealChainRequest struct {
	Steps json.RawMessage `json:"steps"` // []verification.AppealStep — opaque to keep package clean
}

type verifyAppealChainHandler struct{ deps *Dependencies }

func (h *verifyAppealChainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.Context()
	if requireCaller(w, r) == "" {
		return
	}
	if h.deps.Eras == nil {
		writeError(w, http.StatusInternalServerError,
			"era resolution must be configured for appeal-chain verification")
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
	// SDK-4: pin each SOURCE log's burn status (keyed by the same source-log
	// DID VerifyAppealChain resolves the witness set by). A log with no
	// journal entry maps to the zero TrustStatus and fails that hop closed.
	trustByLog := make(map[string]verifier.TrustStatus, len(steps))
	for i := range steps {
		if steps[i].Proof == nil {
			continue
		}
		src := steps[i].Proof.SourceEntry.LogDID
		if _, seen := trustByLog[src]; !seen {
			trustByLog[src] = jntrust.StatusFor(r.Context(), h.deps.HeadsJournal, src)
		}
	}
	verified, err := verification.VerifyAppealChain(r.Context(), steps, h.deps.Eras, trustByLog)
	if err != nil {
		// A warming hop is a RETRYABLE startup state, never a broken chain.
		if errors.Is(err, eras.ErrWarming) {
			w.Header().Set("Retry-After", "5")
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": err.Error(), "class": "warming",
			})
			return
		}
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
	Proof        json.RawMessage `json:"proof"`
	SourceLogDID string          `json:"source_log_did"`
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
	if h.deps.Eras == nil {
		writeError(w, http.StatusInternalServerError, "era resolution not configured")
		return
	}
	// FED-1 #107: era-correct resolution against THIS proof's cosigned head.
	set, eraErr := h.deps.Eras.SetForHead(r.Context(), req.SourceLogDID, proof.SourceTreeHead)
	if eraErr != nil {
		switch {
		case errors.Is(eraErr, eras.ErrNoSuchPeer):
			writeError(w, http.StatusBadRequest, "no trust root configured for source_log_did")
		case errors.Is(eraErr, eras.ErrWarming):
			w.Header().Set("Retry-After", "5")
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": "rotation journal warming up for source_log_did — retry", "class": "warming",
			})
		default:
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"error": eraErr.Error(), "class": "cannot_resolve_era",
			})
		}
		return
	}
	// Self-contained model: the anchor entry embeds the source head + its
	// K-of-N cosignatures, so the consumer recomputes the quorum offline and
	// proves inclusion against the verified head — no extractor indirection.
	trust := jntrust.StatusFor(r.Context(), h.deps.HeadsJournal, req.SourceLogDID)
	verifyErr := anchor.VerifyCrossLog(proof, set, trust)
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
