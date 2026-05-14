/*
FILE PATH: verification/ledger_delegate_query.go

DESCRIPTION:

	Thin HTTP shim over the ledger's GET /v1/query/delegate_did/{did}
	read endpoint (shipped on the ledger in PR-K). The SDK's
	sdklog.LedgerQueryAPI interface in attesta v1.5.1 does NOT yet
	expose this query — the v1.5.x batch added the field to
	ControlHeader but the typed query method is a follow-up. Until
	the SDK ships it, JN's read-time policy enforcement (Stage 6's
	constraint walker) reaches the ledger via this shim.

	# CONTRACT

	Mirrors the SDK's HTTPLedgerQueryAPI response shape verbatim
	(see attesta/log/http_query_api.go::queryListResponse): on 200
	the body is

	  { "entries": [ {sequence_number, log_time, signer_did, ...} ],
	    "count":   <int> }

	Returns []types.EntryWithMetadata with CanonicalBytes==nil per
	the ledger's egress mandate (api/queries.go: "we do NOT return
	bytes from list endpoints"). Consumers must hydrate bytes via
	types.EntryFetcher (GET /v1/entries/{seq}/raw) before passing the
	result to attestation.VerifyEntryAttestationPolicy.

	# SDK MIGRATION

	When sdklog.LedgerQueryAPI grows QueryByDelegateDID the
	DelegateDIDQuerier interface here folds into LedgerQueryAPI and
	callers swap *LedgerDelegateQuerier for the SDK type directly.
	Until then, JN's wiring constructs one of each.

KEY DEPENDENCIES:
  - attesta v1.5.1 types.EntryWithMetadata, types.LogPosition (target shape)
  - Ledger PR-K route: GET /v1/query/delegate_did/{did}
*/
package verification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/clearcompass-ai/attesta/types"
)

// defaultDelegateQueryTimeout caps each delegate_did round-trip. JN's
// read-time policy enforcement budgets for per-entry verification in
// the low-seconds; 15s leaves room for the ledger's own DB query +
// the JSON decode without starving SLOs.
const defaultDelegateQueryTimeout = 15 * time.Second

// maxDelegateQueryResponseBytes caps the response body. A delegate's
// chain is typically <10 hops and metadata-only rows are ~250 bytes;
// 4 MiB allows a 16 000-hop chain before the cap fires (well past any
// reasonable delegation graph).
const maxDelegateQueryResponseBytes = 4 << 20

// ErrDelegateQuery is the umbrella sentinel for every error path the
// shim surfaces. Wraps HTTP, decode, and ledger-side error responses
// uniformly so callers can errors.Is(err, ErrDelegateQuery) to pick
// out "ledger unreachable / malformed" from "no rows" (which is NOT
// an error; an empty slice is returned).
var ErrDelegateQuery = errors.New("verification/ledger_delegate_query")

// DelegateDIDQuerier is the read-time interface JN's Stage 6 uses to
// walk delegation chains. Production wires *LedgerDelegateQuerier;
// tests inject an in-memory fake.
type DelegateDIDQuerier interface {
	// QueryByDelegateDID returns live entries (newest first) whose
	// Header.DelegateDID equals did. CanonicalBytes is nil — the
	// caller hydrates via a types.EntryFetcher before consuming.
	QueryByDelegateDID(ctx context.Context, did string) ([]types.EntryWithMetadata, error)
}

// LedgerDelegateQuerier is the production HTTPS shim against one
// ledger's /v1/query/delegate_did/{did} endpoint. Goroutine-safe;
// share one instance per logical log within a process.
type LedgerDelegateQuerier struct {
	baseURL string
	logDID  string
	client  *http.Client
}

// LedgerDelegateQuerierConfig configures the shim. BaseURL is the
// ledger root (no trailing slash). LogDID populates Position.LogDID
// on returned entries; required because the endpoint URL does not
// carry the log identity (one ledger == one log).
type LedgerDelegateQuerierConfig struct {
	BaseURL string
	LogDID  string
	Timeout time.Duration // default 15s
	Client  *http.Client  // default http.DefaultClient with Timeout
}

// NewLedgerDelegateQuerier constructs the shim. Returns
// ErrDelegateQuery wrapping a precise sub-cause if cfg is malformed.
func NewLedgerDelegateQuerier(cfg LedgerDelegateQuerierConfig) (*LedgerDelegateQuerier, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("%w: BaseURL required", ErrDelegateQuery)
	}
	if cfg.LogDID == "" {
		return nil, fmt.Errorf("%w: LogDID required", ErrDelegateQuery)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultDelegateQueryTimeout
	}
	c := cfg.Client
	if c == nil {
		c = &http.Client{Timeout: timeout}
	}
	return &LedgerDelegateQuerier{
		baseURL: cfg.BaseURL,
		logDID:  cfg.LogDID,
		client:  c,
	}, nil
}

// delegateQueryEntry mirrors api/queries.go::EntryResponse on the
// ledger. Field tags are byte-identical with the SDK's
// queryEntryResponse so a future SDK migration is a type-rename.
type delegateQueryEntry struct {
	SequenceNumber  uint64 `json:"sequence_number"`
	CanonicalHash   string `json:"canonical_hash"`
	LogTime         string `json:"log_time"`
	SignerDID       string `json:"signer_did,omitempty"`
	ProtocolVersion uint16 `json:"protocol_version"`
	PayloadSize     int    `json:"payload_size"`
	CanonicalSize   int    `json:"canonical_size"`
}

// delegateQueryEnvelope mirrors api/queries.go::writeEntriesJSON.
type delegateQueryEnvelope struct {
	Entries []delegateQueryEntry `json:"entries"`
	Count   int                  `json:"count"`
}

// QueryByDelegateDID implements DelegateDIDQuerier against the
// ledger's HTTP surface. Returns an empty slice (not an error) when
// the DID has no live delegations. Wraps every failure with
// ErrDelegateQuery so callers can errors.Is for routing.
func (q *LedgerDelegateQuerier) QueryByDelegateDID(
	ctx context.Context, did string,
) ([]types.EntryWithMetadata, error) {
	if did == "" {
		return nil, fmt.Errorf("%w: empty delegate DID", ErrDelegateQuery)
	}
	endpoint := q.baseURL + "/v1/query/delegate_did/" + url.PathEscape(did)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrDelegateQuery, err)
	}
	resp, err := q.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: HTTP: %w", ErrDelegateQuery, err)
	}
	defer resp.Body.Close()

	// Read cap+1 to surface oversized responses as ledger
	// misbehavior rather than silently truncating; mirrors the
	// pattern in tools/common/ledger_client.go.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDelegateQueryResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %w", ErrDelegateQuery, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d: %s", ErrDelegateQuery, resp.StatusCode, body)
	}
	if len(body) > maxDelegateQueryResponseBytes {
		return nil, fmt.Errorf("%w: response exceeds %d bytes",
			ErrDelegateQuery, maxDelegateQueryResponseBytes)
	}

	var env delegateQueryEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("%w: decode body: %w", ErrDelegateQuery, err)
	}

	out := make([]types.EntryWithMetadata, 0, len(env.Entries))
	for _, r := range env.Entries {
		ewm := types.EntryWithMetadata{
			CanonicalBytes: nil, // egress mandate; caller hydrates
			Position: types.LogPosition{
				LogDID:   q.logDID,
				Sequence: r.SequenceNumber,
			},
		}
		if r.LogTime != "" {
			if t, perr := time.Parse(time.RFC3339Nano, r.LogTime); perr == nil {
				ewm.LogTime = t.UTC()
			}
		}
		out = append(out, ewm)
	}
	return out, nil
}

// Compile-time pin: the shim implements DelegateDIDQuerier.
var _ DelegateDIDQuerier = (*LedgerDelegateQuerier)(nil)
