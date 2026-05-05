/*
FILE PATH: tools/common/ledger_client.go

DESCRIPTION:

	LedgerClient is a thin compatibility shim over the SDK's
	log.HTTPEntryFetcher (/raw → wire bytes) plus a small in-package
	GET against /v1/query/scan (ledger metadata listing). It
	preserves the legacy RawEntry shape so the aggregator (Scanner,
	Reconciler, Deserializer) keeps working while every wire call now
	flows through the SDK-canonical endpoints.

KEY ARCHITECTURAL DECISIONS:
  - SDK is the source of truth for entry-byte retrieval. FetchEntry
    delegates to log.HTTPEntryFetcher (v0.7.75): GET
    /v1/entries/{seq}/raw, auto 302-follow to bucket, X-Sequence
    and X-Log-Time response headers. The fetcher's body cap is
    enforced by the SDK with cap+1 overflow detection (BUG #3).
  - ScanFrom targets the SDK-canonical /v1/query/scan endpoint and
    mirrors the SDK's queryListResponse / queryEntryResponse JSON
    shape exactly. A future PR can swap the in-package GET for a
    direct log.HTTPLedgerQueryAPI call (one-line change); the
    current shim already produces an identical wire request.
  - Each ScanFrom row is back-filled with CanonicalBytes via the SDK
    fetcher because /v1/query/scan deliberately omits the bytes
    (egress mandate, per attesta-ledger/api/queries.go).
  - Connection pooling and 503-Retry-After backpressure come from
    the SDK's log.DefaultClient — every fetcher in the process
    shares the tuned transport.
  - Backwards compatibility: NewLedgerClient(url) still works;
    the optional logDID variadic arg lets callers (the cmd/main
    wiring) pass cfg.CasesLogDID. Without a logDID, ScanFrom returns
    a clear error rather than silently scanning the wrong log.

OVERVIEW:

	NewLedgerClient(baseURL [, logDID])
	FetchEntry(seq) → *RawEntry            (SDK HTTPEntryFetcher)
	ScanFrom(start, count) → []RawEntry    (/v1/query/scan + per-row Fetch)
	TreeHead() → map[string]any            (passthrough)

KEY DEPENDENCIES:
  - attesta/log: HTTPEntryFetcher, DefaultClient
  - attesta/types: EntryWithMetadata, LogPosition
*/
package common

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/types"
)

// defaultLedgerTimeout caps every ledger round-trip (incl. SDK
// 503-Retry-After replays). Matches the prior hand-rolled value.
const defaultLedgerTimeout = 15 * time.Second

// maxScanResponseBytes caps the metadata response body. Sized for a
// 1000-row response (~1 KiB per row) with headroom; matches the SDK's
// pending HTTPLedgerQueryAPI cap.
const maxScanResponseBytes = 16 << 20

// LedgerClient adapts the SDK's HTTP fetcher (and a thin scan
// helper) to the legacy RawEntry API consumed by tools/aggregator.
// Read-only.
type LedgerClient struct {
	baseURL string
	logDID  string
	fetcher *sdklog.HTTPEntryFetcher
	httpc   *http.Client
}

// NewLedgerClient creates a client backed by the SDK fetcher.
// logDID populates types.LogPosition.LogDID on returned entries; pass
// the log DID this process scans against (cfg.CasesLogDID for
// court-tools callers). Without a logDID, FetchEntry still works but
// ScanFrom fails fast.
func NewLedgerClient(baseURL string, optionalLogDID ...string) *LedgerClient {
	logDID := ""
	if len(optionalLogDID) > 0 {
		logDID = optionalLogDID[0]
	}

	fetcher := sdklog.NewHTTPEntryFetcher(sdklog.HTTPEntryFetcherConfig{
		BaseURL: baseURL,
		LogDID:  logDID,
		Timeout: defaultLedgerTimeout,
	})

	// SDK-tuned client for /scan and /tree/head: connection pool
	// of 100 idle conns/host + RetryAfterRoundTripper (BUG #2/#6
	// contract). The SDK fetcher composed above already uses this
	// client internally; the shim's own HTTP path matches.
	return &LedgerClient{
		baseURL: baseURL,
		logDID:  logDID,
		fetcher: fetcher,
		httpc:   sdklog.DefaultClient(defaultLedgerTimeout),
	}
}

// RawEntry is the legacy shape consumed by tools/aggregator. Preserved
// for compatibility; new code should use types.EntryWithMetadata.
type RawEntry struct {
	Sequence         uint64 `json:"sequence"`
	CanonicalHex     string `json:"canonical_hex"`
	LogTimeUnixMicro int64  `json:"log_time_unix_micro"`
	SigAlgoID        uint16 `json:"sig_algo_id,omitempty"`
	SignatureHex     string `json:"signature_hex,omitempty"`
}

// FetchEntry retrieves a single entry by sequence. Returns (nil, nil)
// when the ledger returns 404. Wire path: SDK HTTPEntryFetcher →
// GET /v1/entries/{seq}/raw.
func (c *LedgerClient) FetchEntry(seq uint64) (*RawEntry, error) {
	pos := types.LogPosition{LogDID: c.logDID, Sequence: seq}
	ewm, err := c.fetcher.Fetch(pos)
	if err != nil {
		return nil, fmt.Errorf("ledger: fetch %d: %w", seq, err)
	}
	if ewm == nil {
		return nil, nil
	}
	return entryToRaw(ewm), nil
}

// ScanFrom reads up to count entries starting at startPos. Returns an
// empty slice (not error) at log end. Wire path: GET /v1/query/scan
// (SDK-canonical JSON metadata) + per-row HTTPEntryFetcher.Fetch to
// back-fill CanonicalBytes (the deserializer requires the wire bytes).
func (c *LedgerClient) ScanFrom(startPos uint64, count int) ([]RawEntry, error) {
	if c.logDID == "" {
		return nil, fmt.Errorf("ledger: ScanFrom requires logDID at construction")
	}
	metas, err := c.scanMetadata(startPos, count)
	if err != nil {
		return nil, fmt.Errorf("ledger: scan from %d: %w", startPos, err)
	}
	out := make([]RawEntry, 0, len(metas))
	for _, m := range metas {
		full, fErr := c.fetcher.Fetch(m.Position)
		if fErr != nil {
			return nil, fmt.Errorf("ledger: scan fetch seq %d: %w", m.Position.Sequence, fErr)
		}
		if full == nil {
			// Race: present in scan, gone before /raw. Skip.
			continue
		}
		// Prefer LogTime from /raw header; fall back to the metadata.
		merged := *full
		if merged.LogTime.IsZero() {
			merged.LogTime = m.LogTime
		}
		out = append(out, *entryToRaw(&merged))
	}
	return out, nil
}

// TreeHead fetches the ledger's current tree head. Passthrough —
// the SDK does not yet ship a typed helper for /v1/tree/head.
func (c *LedgerClient) TreeHead() (map[string]any, error) {
	resp, err := c.httpc.Get(c.baseURL + "/v1/tree/head")
	if err != nil {
		return nil, fmt.Errorf("ledger: tree head: %w", err)
	}
	defer resp.Body.Close()

	// BUG #3 mirror: read cap+1 to detect oversize responses
	// instead of silently truncating. Tree heads are tiny
	// (~hundreds of bytes); anything > 64 KiB is ledger
	// misbehavior worth surfacing.
	const treeHeadBodyCap = 64 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, treeHeadBodyCap+1))
	if err != nil {
		return nil, fmt.Errorf("ledger: read tree head: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ledger: tree head: HTTP %d: %s", resp.StatusCode, body)
	}
	if len(body) > treeHeadBodyCap {
		return nil, fmt.Errorf("ledger: tree head response exceeds %d bytes", treeHeadBodyCap)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("ledger: parse tree head: %w", err)
	}
	return result, nil
}

// ─────────────────────────────────────────────────────────────────────
// Internal: /v1/query/scan helper
// ─────────────────────────────────────────────────────────────────────
//
// Mirrors the SDK's pending HTTPLedgerQueryAPI shape exactly. When
// the SDK pin is bumped to include HTTPLedgerQueryAPI, this helper
// becomes a single delegated call.

// scanEntryResponse is one row of /v1/query/scan. Field tags match
// attesta-ledger/api/queries.go::EntryResponse and the SDK's
// queryEntryResponse byte-for-byte.
type scanEntryResponse struct {
	SequenceNumber  uint64 `json:"sequence_number"`
	CanonicalHash   string `json:"canonical_hash"`
	LogTime         string `json:"log_time"`
	SignerDID       string `json:"signer_did,omitempty"`
	ProtocolVersion uint16 `json:"protocol_version"`
	PayloadSize     int    `json:"payload_size"`
	CanonicalSize   int    `json:"canonical_size"`
}

// scanListResponse mirrors the ledger's outer JSON envelope.
type scanListResponse struct {
	Entries []scanEntryResponse `json:"entries"`
	Count   int                 `json:"count"`
}

// scanMetadata calls /v1/query/scan and returns SDK-shaped
// EntryWithMetadata (CanonicalBytes nil — egress mandate).
func (c *LedgerClient) scanMetadata(startPos uint64, count int) ([]types.EntryWithMetadata, error) {
	v := url.Values{}
	v.Set("start", strconv.FormatUint(startPos, 10))
	if count > 0 {
		v.Set("count", strconv.Itoa(count))
	}
	resp, err := c.httpc.Get(c.baseURL + "/v1/query/scan?" + v.Encode())
	if err != nil {
		return nil, fmt.Errorf("scan request: %w", err)
	}
	defer resp.Body.Close()

	// BUG #3 mirror: read cap+1 to detect oversize responses
	// instead of silently truncating. The ledger caps scan
	// payload at maxScanResponseBytes; anything past that is
	// ledger misbehavior the consumer must see.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxScanResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("scan read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scan HTTP %d: %s", resp.StatusCode, body)
	}
	if len(body) > maxScanResponseBytes {
		return nil, fmt.Errorf("scan response exceeds %d bytes", maxScanResponseBytes)
	}

	var list scanListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("scan parse: %w", err)
	}

	out := make([]types.EntryWithMetadata, 0, len(list.Entries))
	for _, r := range list.Entries {
		ewm := types.EntryWithMetadata{
			Position: types.LogPosition{LogDID: c.logDID, Sequence: r.SequenceNumber},
		}
		if r.LogTime != "" {
			if t, err := time.Parse(time.RFC3339Nano, r.LogTime); err == nil {
				ewm.LogTime = t.UTC()
			}
		}
		out = append(out, ewm)
	}
	return out, nil
}

// entryToRaw flattens an SDK EntryWithMetadata into the legacy
// RawEntry shape. CanonicalBytes is hex-encoded for the deserializer;
// LogTime is converted to micros to match the legacy field.
func entryToRaw(ewm *types.EntryWithMetadata) *RawEntry {
	r := &RawEntry{
		Sequence:     ewm.Position.Sequence,
		CanonicalHex: hex.EncodeToString(ewm.CanonicalBytes),
	}
	if !ewm.LogTime.IsZero() {
		r.LogTimeUnixMicro = ewm.LogTime.UnixMicro()
	}
	return r
}
