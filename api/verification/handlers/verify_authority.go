package handlers

import (
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// VerifyAuthorityHandler handles GET /v1/verify/authority/{logID}/{pos}.
//
// C-4 of PR-C: the handler accepts an OPTIONAL ?as_of=<sequence>
// query parameter that pins the cosigned head the authority walker
// evaluates against. Default (no param OR ?as_of=0) → verifier.AsOf{}
// — "latest known head" — preserves the v1.33 read-side surface
// behavior. A non-zero ?as_of= pins the verdict to a SPECIFIC head:
// every signer-membership / activation check is then evaluated
// under THAT head's witness set, making the verdict deterministic
// in the head (Goal 6 — court-admissible reproducibility) and the
// witness set frozen across rotations (Goal 13 — year-15
// verification of year-1 bundles).
type VerifyAuthorityHandler struct{ deps *Dependencies }

func NewVerifyAuthorityHandler(deps *Dependencies) *VerifyAuthorityHandler {
	return &VerifyAuthorityHandler{deps: deps}
}

func (h *VerifyAuthorityHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logID := r.PathValue("logID")
	posStr := r.PathValue("pos")

	pos, err := strconv.ParseUint(posStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid position")
		return
	}

	asOf, err := parseAsOf(r, logID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	fetcher, err := h.deps.fetcherFor(logID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	entity := types.LogPosition{LogDID: logID, Sequence: pos}

	result, err := verifier.EvaluateAuthorityWithTrust(
		ctx, entity, h.deps.PickTrust(fetcher),
		h.deps.Extractor, asOf)

	if err != nil {
		writeError(w, http.StatusInternalServerError, "authority evaluation failed")
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// parseAsOf reads ?as_of=<sequence> from r and returns the
// corresponding verifier.AsOf. An absent / empty / zero value
// returns AsOf{} (latest). A non-empty malformed value returns a
// 400-shaped error. The LogDID is bound to the asOf so the
// MultiJurisdictionTrust foreign-log path resolves the right log's
// journal entry.
func parseAsOf(r *http.Request, logID string) (verifier.AsOf, error) {
	raw := r.URL.Query().Get("as_of")
	if raw == "" {
		return verifier.AsOf{}, nil
	}
	seq, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return verifier.AsOf{}, errBadAsOf
	}
	if seq == 0 {
		return verifier.AsOf{}, nil
	}
	return verifier.AsOf{LogDID: logID, Sequence: seq}, nil
}

// errBadAsOf is the sentinel parseAsOf returns for a malformed
// ?as_of= value. The handlers surface its Error() as a 400 body.
var errBadAsOf = badAsOfError("invalid as_of: expected a non-negative integer sequence")

type badAsOfError string

func (e badAsOfError) Error() string { return string(e) }
