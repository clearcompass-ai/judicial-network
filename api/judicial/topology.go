/*
FILE PATH: api/judicial/topology.go

DESCRIPTION:

	Topology handlers — wired with the witness.TreeHeadClient that
	-C6 stubbed as 501. The two endpoints:

	  POST /v1/judicial/topology/publish-anchor
	    Builds the anchor commentary entry the ledger submits to
	    a parent (state) log. Wraps topology.PublishAnchor which
	    fetches the latest cosigned tree head from the source log
	    via deps.TreeHeadClient.

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
	"net/http"

	"github.com/clearcompass-ai/judicial-network/topology"
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
	signer := requireCaller(w, r)
	if signer == "" {
		return
	}
	if h.deps.TreeHeadClient == nil {
		writeError(w, http.StatusServiceUnavailable,
			"topology.publish-anchor requires a configured *witness.TreeHeadClient; "+
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
	res, err := topology.PublishAnchor(topology.AnchorConfig{
		Destination:  req.Destination,
		SignerDID:    signer,
		SourceLogDID: req.SourceLogDID,
		EventTime:    req.EventTime,
	}, h.deps.TreeHeadClient)
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
	res, err := topology.DiscoverAnchorChain(courtDID, h.deps.Hierarchy, h.deps.Resolver, h.deps.TreeHeadClient)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
	_ = json.RawMessage{}
}
