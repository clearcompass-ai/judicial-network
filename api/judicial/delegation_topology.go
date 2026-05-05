/*
FILE PATH: api/judicial/delegation_topology.go

DESCRIPTION:

	Delegation handlers + the route-registration glue for both
	delegation and topology surfaces.

	Delegation issue/revoke/succeed are 501 stubs because they need
	a long-lived BuildContext (Identity provider + Submitter +
	Catalog) that boots once at process start, not per-request.

	Topology handlers (publish-anchor + anchor-chain) live in
	topology.go and are now WIRED with deps.TreeHeadClient + (for
	anchor-chain) deps.Hierarchy. They surface 503 when their
	required deps are nil so the binary boots cleanly without
	witness configuration but routes refuse traffic until configured.

	  POST /v1/judicial/delegation/issue        → 501 (BuildContext)
	  POST /v1/judicial/delegation/revoke       → 501 (BuildContext)
	  POST /v1/judicial/delegation/succeed      → 501 (BuildContext)
	  POST /v1/judicial/topology/publish-anchor → wired (topology.go)
	  GET  /v1/judicial/topology/anchor-chain   → wired (topology.go)
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
// delegation/* — BuildContext-bound (501 stubs)
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
