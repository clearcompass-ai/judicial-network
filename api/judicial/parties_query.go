/*
FILE PATH: api/judicial/parties_query.go

DESCRIPTION:

	Read-side party-binding queries.

	  GET /v1/judicial/parties/bindings?signer_did=...
	                                             → ListCaseParties
	  GET /v1/judicial/parties/bindings/by-id/{bindingID}?signer_did=...
	                                             → FindPartyByBindingID

	Both require an X-Parties-Log-DID header — same pattern as
	cases/lookup. Production deployments may auto-derive in a
	future patch.
*/
package judicial

import (
	"context"
	"fmt"
	"net/http"

	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/parties"
)

// partiesQuerierAdapter wraps a ctx-aware LedgerQueryAPI so it
// satisfies the parties.PartiesQuerier interface (which also takes
// ctx in v0.3.0). Both signatures match; the adapter exists only to
// constrain the embedded api to the two methods PartiesQuerier
// requires.
type partiesQuerierAdapter struct {
	api interface {
		QueryBySignerDID(ctx context.Context, did string) ([]types.EntryWithMetadata, error)
		QueryByTargetRoot(ctx context.Context, pos types.LogPosition) ([]types.EntryWithMetadata, error)
	}
}

func (a partiesQuerierAdapter) QueryBySignerDID(ctx context.Context, did string) ([]types.EntryWithMetadata, error) {
	return a.api.QueryBySignerDID(ctx, did)
}

func (a partiesQuerierAdapter) QueryByTargetRoot(ctx context.Context, pos types.LogPosition) ([]types.EntryWithMetadata, error) {
	return a.api.QueryByTargetRoot(ctx, pos)
}

type partyBindingListHandler struct{ deps *Dependencies }

func (h *partyBindingListHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if requireCaller(w, r) == "" {
		return
	}
	// Caller may query for any signer's bindings (clerks audit
	// across; defendants only see their own). Production deployment
	// gates this via roster + scope check; for the API surface,
	// the signer_did query param is the lookup key.
	signerDID := r.URL.Query().Get("signer_did")
	if signerDID == "" {
		writeError(w, http.StatusBadRequest, "signer_did query param required")
		return
	}
	q, err := h.partiesQuerier(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	links, err := parties.ListCaseParties(ctx, signerDID, q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, links)
}

func (h *partyBindingListHandler) partiesQuerier(r *http.Request) (parties.PartiesQuerier, error) {
	logDID := r.Header.Get("X-Parties-Log-DID")
	if logDID == "" {
		return nil, fmt.Errorf("X-Parties-Log-DID header required")
	}
	q, ok := h.deps.LogQueries[logDID]
	if !ok {
		return nil, fmt.Errorf("no LogQueries entry for %s", logDID)
	}
	return partiesQuerierAdapter{api: q}, nil
}

type partyBindingFindHandler struct{ deps *Dependencies }

func (h *partyBindingFindHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if requireCaller(w, r) == "" {
		return
	}
	bindingID := r.PathValue("bindingID")
	if bindingID == "" {
		writeError(w, http.StatusBadRequest, "bindingID required")
		return
	}
	signerDID := r.URL.Query().Get("signer_did")
	if signerDID == "" {
		writeError(w, http.StatusBadRequest, "signer_did query param required")
		return
	}
	q, err := h.partiesQuerier(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	link, err := parties.FindPartyByBindingID(ctx, signerDID, bindingID, q)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, link)
}

func (h *partyBindingFindHandler) partiesQuerier(r *http.Request) (parties.PartiesQuerier, error) {
	logDID := r.Header.Get("X-Parties-Log-DID")
	if logDID == "" {
		return nil, fmt.Errorf("X-Parties-Log-DID header required")
	}
	q, ok := h.deps.LogQueries[logDID]
	if !ok {
		return nil, fmt.Errorf("no LogQueries entry for %s", logDID)
	}
	return partiesQuerierAdapter{api: q}, nil
}

// (Legacy adapter definition removed; consolidated at top of file
// under ctx-aware v0.3.0 signatures.)
