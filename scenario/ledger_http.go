package scenario

// The live ledger transport: the production delegation.LedgerSubmitter and a
// thin read client, so the scenario's seeder + generators drive a REAL ledger
// over HTTP rather than the in-memory fake the tests use.
//
// Write path (HTTPLedgerSubmitter):
//   POST {base}/v1/entries        — canonical bytes, application/octet-stream,
//                                   Mode-A credit token as Authorization: Bearer
//   GET  {base}/v1/entries-hash/{canonical_hash} — poll until sequenced
// Both halves live in tooling/libs/cli (SubmitWire + WaitForSequence, composed
// as SubmitWireAndWait) — the ONE shared "direct-to-ledger" primitive every
// baseproof submit tool uses, so the scenario speaks exactly the wire the
// judicial-cli, submit-stamp, and the JN exchange forward all speak.
//
// Read path (LedgerReader): the ledger's pure-JSON surface (no wire format),
// used to confirm commits and report the populated tree.
//
// TLS: callers pass an *http.Client. Against the e2e stack the ledger serves
// self-signed HTTPS, so the client's RootCAs must pin the run CA (see
// cmd/scenario, -ca-cert); a plain http:// endpoint needs no special client.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/baseproof/tooling/libs/cli"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// HTTPLedgerSubmitter is the live delegation.LedgerSubmitter: it submits one
// signed canonical entry to a ledger and returns the on-log position the
// ledger assigned it. It is the production counterpart to the tests'
// memLedger — the seam delegation.BuildContext.Submitter plugs into.
//
// One submitter targets one ledger serving one log; LogDID is stamped onto
// every returned LogPositionRef (the ledger's entries-hash poll yields the
// sequence, not the log DID, so the submitter supplies it).
type HTTPLedgerSubmitter struct {
	baseURL string // ledger base URL, e.g. https://localhost:8080
	logDID  string // the log this ledger serves → LogPositionRef.LogDID
	token   string // Mode-A credit bearer token; "" ⇒ Mode B (PoW), which the scenario does not stamp
	hc      *http.Client
	timeout time.Duration // per-entry sequence-wait budget
}

// NewHTTPLedgerSubmitter builds a submitter for the ledger at baseURL serving
// logDID. token is the Mode-A credit bearer token (the e2e default is
// "baseproof-mode-a"); pass "" only against a PoW-free / ungated dev ledger.
// hc must trust the ledger's server cert (pin the run CA for the e2e stack).
func NewHTTPLedgerSubmitter(baseURL, logDID, token string, hc *http.Client, waitTimeout time.Duration) *HTTPLedgerSubmitter {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	if waitTimeout <= 0 {
		waitTimeout = 120 * time.Second
	}
	return &HTTPLedgerSubmitter{baseURL: baseURL, logDID: logDID, token: token, hc: hc, timeout: waitTimeout}
}

// SubmitCanonical implements delegation.LedgerSubmitter: POST the bytes, wait
// for the ledger to sequence them, and return {logDID, sequence}. A non-202
// from admission (a gate rejection or a PoW/credit refusal) surfaces verbatim
// from SubmitWire; a 202 that never sequences within the budget surfaces from
// WaitForSequence.
func (s *HTTPLedgerSubmitter) SubmitCanonical(ctx context.Context, canonical []byte) (schemas.LogPositionRef, error) {
	seq, err := cli.SubmitWireAndWait(ctx, s.hc, s.baseURL, s.token, canonical, s.timeout)
	if err != nil {
		return schemas.LogPositionRef{}, fmt.Errorf("ledger %s: %w", s.baseURL, err)
	}
	return schemas.LogPositionRef{LogDID: s.logDID, Sequence: seq}, nil
}

// LogDID reports the log this submitter writes to.
func (s *HTTPLedgerSubmitter) LogDID() string { return s.logDID }

// LedgerReader reads a ledger's pure-JSON endpoints. Reads are open (server
// verifies its own cert; no client cert), so the reader needs only a
// CA-trusting client.
type LedgerReader struct {
	baseURL string
	hc      *http.Client
}

// NewLedgerReader builds a reader for the ledger at baseURL.
func NewLedgerReader(baseURL string, hc *http.Client) *LedgerReader {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &LedgerReader{baseURL: baseURL, hc: hc}
}

// TreeHead is the subset of GET /v1/tree/head the scenario asserts on.
type TreeHead struct {
	TreeSize   uint64            `json:"tree_size"`
	Signatures []json.RawMessage `json:"signatures"`
}

// Head fetches the current cosigned tree head.
func (r *LedgerReader) Head(ctx context.Context) (*TreeHead, error) {
	var h TreeHead
	if err := r.getJSON(ctx, "/v1/tree/head", &h); err != nil {
		return nil, err
	}
	return &h, nil
}

// Healthy reports whether GET /healthz returns the literal "ok".
func (r *LedgerReader) Healthy(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := r.hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	buf := make([]byte, 2)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n]) == "ok"
}

// Entry fetches the JSON metadata for a sequence (GET /v1/entries/{seq}).
func (r *LedgerReader) Entry(ctx context.Context, seq uint64) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := r.getJSON(ctx, "/v1/entries/"+strconv.FormatUint(seq, 10), &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// Inclusion fetches a Merkle inclusion proof for a sequence
// (GET /v1/tree/inclusion/{seq}): {leaf_index, tree_size, hashes}.
func (r *LedgerReader) Inclusion(ctx context.Context, seq uint64) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := r.getJSON(ctx, "/v1/tree/inclusion/"+strconv.FormatUint(seq, 10), &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func (r *LedgerReader) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := r.hc.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("GET %s: decode: %w", path, err)
	}
	return nil
}
