/*
FILE PATH: api/judicial/topology.go

DESCRIPTION:

	Topology handlers — wired with the witness.TreeHeadClient that
	-C6 stubbed as 501. The two endpoints:

	  POST /v1/judicial/topology/publish-anchor
	    Builds the anchor commentary entry the ledger submits to
	    a parent (state) log. Wraps topology.PublishAnchor which
	    fetches the latest cosigned tree head from the source log
	    via deps.TreeHeadClient. v0.3.0: reads NetworkID from the
	    encapsulated WitnessKeySet (not from a parallel map).

	  GET  /v1/judicial/topology/anchor-chain
	    Walks the anchor hierarchy from the supplied court DID up
	    to the state root. Wraps topology.DiscoverAnchorChain which
	    consults deps.Resolver for DID Documents and deps.TreeHeadClient
	    for cached tree heads at each hop.

	Both handlers return 503 with a clear reason when their
	required deps are nil — the binary boots cleanly without
	witness configuration but the routes refuse traffic until
	operational config wires the TreeHeadClient + (for anchor-
	chain) the Hierarchy.
*/
package judicial

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/clearcompass-ai/judicial-network/topology"

	"github.com/clearcompass-ai/judicial-network/verification/eras"
)

// ─────────────────────────────────────────────────────────────────────
// publish-anchor
// ─────────────────────────────────────────────────────────────────────

type topologyPublishAnchorRequest struct {
	Destination  string `json:"destination"`
	SourceLogDID string `json:"source_log_did"`
	EventTime    int64  `json:"event_time,omitempty"`
}

type topologyPublishAnchorHandler struct{ deps *Dependencies }

func (h *topologyPublishAnchorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	if h.deps.CheckpointClient == nil {
		writeError(w, http.StatusServiceUnavailable,
			"topology.publish-anchor requires a configured checkpoint client; "+
				"populate witness operational config + restart")
		return
	}
	var req topologyPublishAnchorRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Destination == "" || req.SourceLogDID == "" {
		writeError(w, http.StatusBadRequest,
			"destination and source_log_did required")
		return
	}
	// FED-1 #107: the anchor publisher is a CURRENT-set consumer (it fetches
	// and verifies a LIVE horizon — no proof head exists yet), so it resolves
	// the newest set the journaled chain can prove. NetworkID lives inside
	// the encapsulated WitnessKeySet (SDK Principle 10), so keys+K+network
	// stay in sync by construction. If the live log has rotated beyond the
	// chain we hold, the downstream horizon verification fails closed and
	// gossip catches the chain up.
	if h.deps.Eras == nil {
		writeError(w, http.StatusInternalServerError, "era resolution not configured")
		return
	}
	set, eraErr := h.deps.Eras.CurrentSet(ctx, req.SourceLogDID)
	if eraErr != nil {
		if errors.Is(eraErr, eras.ErrNoSuchPeer) {
			writeError(w, http.StatusServiceUnavailable,
				"topology.publish-anchor requires a trust root for source_log_did; configure it at boot + restart")
			return
		}
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error": eraErr.Error(), "class": "cannot_resolve_era",
		})
		return
	}
	networkID := set.NetworkID()
	res, err := topology.PublishAnchor(ctx, topology.AnchorConfig{
		Destination:  req.Destination,
		SignerDID:    signer,
		SourceLogDID: req.SourceLogDID,
		EventTime:    req.EventTime,
		NetworkID:    networkID,
	}, h.deps.CheckpointClient, set)

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// AnchorResult carries TreeHeadRef + TreeSize alongside the
	// unsigned entry; surface both so the caller can audit the
	// anchored head before signing.
	resp := struct {
		buildResponse
		TreeHeadRef string `json:"tree_head_ref"`
		TreeSize    uint64 `json:"tree_size"`
	}{
		TreeHeadRef: res.TreeHeadRef,
		TreeSize:    res.TreeSize,
	}
	writeBuildResponseTo(&resp.buildResponse, res.Entry)
	writeJSON(w, http.StatusOK, resp)
}

// ─────────────────────────────────────────────────────────────────────
// anchor-chain
// ─────────────────────────────────────────────────────────────────────

type topologyAnchorChainHandler struct{ deps *Dependencies }

func (h *topologyAnchorChainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if requireCaller(w, r) == "" {
		return
	}
	if h.deps.TreeHeadClient == nil {
		writeError(w, http.StatusServiceUnavailable,
			"topology.anchor-chain requires a configured *witness.TreeHeadClient; "+
				"populate witness operational config + restart")
		return
	}
	if h.deps.Hierarchy == nil {
		writeError(w, http.StatusServiceUnavailable,
			"topology.anchor-chain requires a configured *topology.Hierarchy; "+
				"populate topology operational config + restart")
		return
	}
	courtDID := r.URL.Query().Get("court_did")
	if courtDID == "" {
		writeError(w, http.StatusBadRequest, "court_did query param required")
		return
	}
	res, err := topology.DiscoverAnchorChain(ctx, courtDID, h.deps.Hierarchy, h.deps.Resolver, h.deps.TreeHeadClient)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
	_ = json.RawMessage{}
}
