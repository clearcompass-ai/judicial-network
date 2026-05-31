package handlers

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"

	"github.com/clearcompass-ai/attesta-tools/libs/monitoring"
)

// VerifyAuthorityHandler handles GET /v1/verify/authority/{logID}/{pos}.
//
// The handler accepts an OPTIONAL ?as_of=<sequence> query parameter
// pinning the cosigned head the authority walker evaluates against.
// Under the attesta v1.43.0 Temporal-Anchor mandate (ZT-IMM-01) there
// is NO implicit wall-clock "latest": absent / empty / ?as_of=0 →
// resolveAsOf snapshots the CURRENT head into a pinned AsOf
// (verifier.ResolveLatest); ?as_of=N pins the journaled head
// at-or-before N. Either way the returned AsOf carries a RootHash, so
// every signer-membership / activation check is evaluated under THAT
// exact head's witness set — the verdict is deterministic and
// reproducible (Goal 6 — court-admissible) and the witness set is
// frozen across rotations (Goal 13 — year-15 verification).
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

	fetcher, err := h.deps.fetcherFor(logID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	prov := h.deps.PickTrust(fetcher)

	// ZT-IMM-01: pin the head BEFORE evaluating; never an implicit latest.
	asOf, err := resolveAsOf(ctx, r, logID, prov, h.deps.Journal)
	if err != nil {
		writeError(w, asOfErrorStatus(err), err.Error())
		return
	}

	entity := types.LogPosition{LogDID: logID, Sequence: pos}

	result, err := verifier.EvaluateAuthorityWithTrust(
		ctx, entity, prov, h.deps.Extractor, asOf)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authority evaluation failed")
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// asOfRequest parses the optional ?as_of=<sequence> query parameter
// into a sequence intent: (seq, explicit, err). explicit == false
// means "no historical pin requested" (absent / empty / ?as_of=0) —
// the caller resolves the current head. explicit == true with seq > 0
// is a historical pin. A non-numeric / negative value returns
// errBadAsOf (surfaced as 400). Pure (no I/O) so it is unit-testable
// without a provider or journal.
func asOfRequest(r *http.Request) (seq uint64, explicit bool, err error) {
	raw := r.URL.Query().Get("as_of")
	if raw == "" {
		return 0, false, nil
	}
	n, perr := strconv.ParseUint(raw, 10, 64)
	if perr != nil {
		return 0, false, errBadAsOf
	}
	if n == 0 {
		return 0, false, nil
	}
	return n, true, nil
}

// resolveAsOf turns the request's as_of intent into a PINNED
// verifier.AsOf, honoring the attesta v1.43.0 Temporal-Anchor mandate
// (ZT-IMM-01): there is no implicit wall-clock latest, and every pin
// carries a RootHash (ErrRootHashRequired otherwise).
//
//   - absent / empty / ?as_of=0 → verifier.ResolveLatest snapshots
//     prov's current cosigned head into a pinned (Sequence, RootHash)
//     selector — the single, deliberate, auditable "now".
//   - ?as_of=N → the burn-free journaled head at-or-before N supplies
//     the RootHash (there is no SDK resolve-by-sequence; the heads
//     journal is JN's verified-head source). A nil journal, or a
//     burned/absent head, fails closed.
//
// It NEVER returns the zero AsOf, so a downstream verdict primitive
// can never hit ErrAsOfRequired / ErrRootHashRequired on a value this
// produced.
func resolveAsOf(
	ctx context.Context,
	r *http.Request,
	logID string,
	prov verifier.LogTrustProvider,
	journal monitoring.HeadsJournal,
) (verifier.AsOf, error) {
	seq, explicit, err := asOfRequest(r)
	if err != nil {
		return verifier.AsOf{}, err
	}
	if !explicit {
		// The one explicit, reproducible "latest" (ZT-IMM-01).
		return verifier.ResolveLatest(ctx, prov, logID)
	}
	if journal == nil {
		return verifier.AsOf{}, errNoJournal
	}
	head, err := journal.HeadAt(ctx, logID, seq)
	if err != nil {
		return verifier.AsOf{}, err
	}
	// Mirror verifier.AsOfFromHead: pin the head's last committed
	// position AND its RootHash (fork-exact).
	return verifier.AsOf{
		LogPosition: types.LogPosition{LogDID: logID, Sequence: head.TreeSize - 1},
		RootHash:    head.RootHash,
	}, nil
}

// asOfErrorStatus maps a resolveAsOf failure to an HTTP status: a
// malformed ?as_of= is the client's fault (400); anything else (no
// head to pin, burned log, journal error) is a server/state condition
// (500).
func asOfErrorStatus(err error) int {
	if errors.Is(err, errBadAsOf) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// errBadAsOf is the sentinel for a malformed ?as_of= value (400).
var errBadAsOf = badAsOfError("invalid as_of: expected a non-negative integer sequence")

// errNoJournal is returned when an explicit historical ?as_of=N pin is
// requested but no heads journal is wired to supply the head's RootHash.
var errNoJournal = errors.New("as_of=N historical pin requires a heads journal; none configured")

type badAsOfError string

func (e badAsOfError) Error() string { return string(e) }
