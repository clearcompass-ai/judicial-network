/*
FILE PATH: api/judicial/delegation_topology.go

DESCRIPTION:
    Delegation + topology handlers. All five entry points are
    operational-tooling territory rather than per-request HTTP shapes:

      - delegation.Issue/Revoke/Succeed need a long-lived
        BuildContext (Identity provider + Submitter + Catalog) that
        boots once at process start, not per-request.
      - topology.PublishAnchor + DiscoverAnchorChain need a
        *witness.TreeHeadClient with cosigned-head caches that are
        likewise process-scoped.

    Exposing these as wire endpoints would force callers to ship
    state that should never leave the binary. Instead the routes
    here advertise the contract (auth-gated, JSON-shaped) and return
    501 with the operational reasoning so downstream tooling knows
    why the JN binary itself is the right caller.

      POST /v1/judicial/delegation/issue        → 501 (BuildContext)
      POST /v1/judicial/delegation/revoke       → 501 (BuildContext)
      POST /v1/judicial/delegation/succeed      → 501 (BuildContext)
      POST /v1/judicial/topology/publish-anchor → 501 (TreeHeadClient)
      GET  /v1/judicial/topology/anchor-chain   → 501 (TreeHeadClient)
*/
package judicial

import "net/http"

func registerDelegationTopologyRoutes(mux *http.ServeMux, deps *Dependencies) {
	mux.Handle("POST /v1/judicial/delegation/issue", &delegationIssueHandler{deps: deps})
	mux.Handle("POST /v1/judicial/delegation/revoke", &delegationRevokeHandler{deps: deps})
	mux.Handle("POST /v1/judicial/delegation/succeed", &delegationSucceedHandler{deps: deps})
	mux.Handle("POST /v1/judicial/topology/publish-anchor", &topologyPublishAnchorHandler{deps: deps})
	mux.Handle("GET /v1/judicial/topology/anchor-chain", &topologyAnchorChainHandler{deps: deps})
}

// ─────────────────────────────────────────────────────────────────────
// delegation/* — BuildContext-bound
// ─────────────────────────────────────────────────────────────────────

type delegationIssueHandler struct{ deps *Dependencies }

func (h *delegationIssueHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"delegation.Issue requires a process-scoped BuildContext (Identity + Submitter + Catalog); "+
			"composed by the JN binary at boot, not per-request")
}

type delegationRevokeHandler struct{ deps *Dependencies }

func (h *delegationRevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"delegation.Revoke requires a process-scoped BuildContext; composed by the JN binary at boot")
}

type delegationSucceedHandler struct{ deps *Dependencies }

func (h *delegationSucceedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"delegation.Succeed requires a process-scoped BuildContext; composed by the JN binary at boot")
}

// ─────────────────────────────────────────────────────────────────────
// topology/* — TreeHeadClient-bound
// ─────────────────────────────────────────────────────────────────────

type topologyPublishAnchorHandler struct{ deps *Dependencies }

func (h *topologyPublishAnchorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"topology.PublishAnchor requires a *witness.TreeHeadClient with a cosigned-head cache; "+
			"process-scoped, composed by the JN binary at boot")
}

type topologyAnchorChainHandler struct{ deps *Dependencies }

func (h *topologyAnchorChainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if requireCaller(w, r) == "" {
		return
	}
	writeError(w, http.StatusNotImplemented,
		"topology.DiscoverAnchorChain requires a *witness.TreeHeadClient + Hierarchy snapshot; "+
			"process-scoped, composed by the JN binary at boot")
}
