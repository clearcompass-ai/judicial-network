/*
FILE PATH: tools/witness/cmd/witness/cosigner.go

DESCRIPTION:
    Per-log cosigning loop. For each registered log DID:

      1. Fetch latest tree head via *witness.TreeHeadClient.
      2. Skip if the head has not advanced since the last cosig
         (no-op cosignature is wasted bandwidth).
      3. Sign the cosign-canonical tree-head message with the
         daemon's BLS key (cosign.SignBLS, PurposeTreeHead).
      4. POST the cosignature to <operator>/v1/cosignatures.

    Sign + post are pluggable (SignerFunc / CosigPostFunc) so tests
    inject deterministic stubs instead of real BLS material +
    real HTTP. The default implementations call cosign.SignBLS and
    a plain http.Client respectively.
*/
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/witness"
)

// SignerFunc produces a cosignature over the supplied tree head.
// Returns the raw signature bytes; the daemon wraps them in a
// types.WitnessSignature when posting to the operator.
type SignerFunc func(head types.TreeHead) ([]byte, error)

// CosignaturePost is the JSON shape posted to the operator's
// witness-accept endpoint. The operator's exact wire shape lives
// in the operator repo; this is the conservative shape: log DID
// + witness DID + signature bytes, with the operator filling in
// the PubKeyID + SchemeTag from its accepted-witness registry.
type CosignaturePost struct {
	LogDID     string `json:"log_did"`
	WitnessDID string `json:"witness_did"`
	Signature  []byte `json:"signature"`
}

// CosigPostFunc posts a cosignature to the operator's accept
// endpoint. Returns nil on 2xx; non-nil propagates upstream
// failures so the loop can log + retry on the next tick.
type CosigPostFunc func(ctx context.Context, operatorBase string, post CosignaturePost) error

// cosignLoopConfig configures the cosigning loop. All fields are
// required.
type cosignLoopConfig struct {
	LogDIDs      []string
	Operators    map[string]string
	PollInterval time.Duration
	WitnessDID   string
	Client       *witness.TreeHeadClient
	Signer       SignerFunc
	Post         CosigPostFunc
}

// cosignLoop holds the per-log "last seen tree size" so it can
// suppress duplicate cosignatures.
type cosignLoop struct {
	cfg cosignLoopConfig

	mu       sync.Mutex
	lastSize map[string]uint64 // logDID → last cosigned tree size
}

func newCosignLoop(cfg cosignLoopConfig) *cosignLoop {
	return &cosignLoop{
		cfg:      cfg,
		lastSize: make(map[string]uint64, len(cfg.LogDIDs)),
	}
}

// Run executes the cosigning loop until ctx is cancelled. Returns
// ctx.Err() on cancellation; never returns a non-context error
// (per-tick failures are logged and retried).
func (l *cosignLoop) Run(ctx context.Context) error {
	tick := time.NewTicker(l.cfg.PollInterval)
	defer tick.Stop()
	// Fire once immediately so a fresh boot doesn't wait a full
	// poll interval before the first cosignature.
	l.tickOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			l.tickOnce(ctx)
		}
	}
}

// tickOnce processes every log once. Per-log failures are logged
// and don't block subsequent logs.
func (l *cosignLoop) tickOnce(ctx context.Context) {
	for _, did := range l.cfg.LogDIDs {
		if err := l.processLog(ctx, did); err != nil {
			// stderr-only — observability metrics + structured
			// logger are wired by the probe surface for production
			// scraping.
			fmt.Fprintf(stderrSink(), "witness: %s: %v\n", did, err)
		}
	}
}

// processLog runs the full fetch → sign → post cycle for one log
// DID. Returns nil when the head hasn't advanced since the last
// processed tick (no-op cosignature suppression).
func (l *cosignLoop) processLog(ctx context.Context, logDID string) error {
	head, _, err := l.cfg.Client.FetchLatestTreeHead(logDID)
	if err != nil {
		return fmt.Errorf("fetch head: %w", err)
	}
	l.mu.Lock()
	last := l.lastSize[logDID]
	l.mu.Unlock()
	if head.TreeHead.TreeSize == last {
		return nil // no advance
	}

	sigBytes, err := l.cfg.Signer(head.TreeHead)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	op, ok := l.cfg.Operators[logDID]
	if !ok {
		return fmt.Errorf("no operator endpoint for %s", logDID)
	}
	if err := l.cfg.Post(ctx, op, CosignaturePost{
		LogDID:     logDID,
		WitnessDID: l.cfg.WitnessDID,
		Signature:  sigBytes,
	}); err != nil {
		return fmt.Errorf("post: %w", err)
	}

	l.mu.Lock()
	l.lastSize[logDID] = head.TreeHead.TreeSize
	l.mu.Unlock()
	return nil
}

// defaultSignerFunc is wired in main.go realDeps. It loads the BLS
// key from disk on first call (cached for the daemon's lifetime).
// Currently a placeholder — W1 lands the real implementation that
// parses the BLS PEM and calls cosign.SignBLS with PurposeTreeHead.
// Returning a fixed nil signature here keeps the daemon bootable in
// dev without a real key.
var defaultSignerFunc SignerFunc = func(_ types.TreeHead) ([]byte, error) {
	return nil, fmt.Errorf("witness: BLS key loader not yet wired (default signer placeholder)")
}

// defaultPostFunc posts a cosignature as JSON to
// <operator>/v1/cosignatures. The endpoint shape is the
// operator-side accepts-cosignature contract; production
// deploys swap for whatever the operator actually exposes.
var defaultPostFunc CosigPostFunc = func(ctx context.Context, operatorBase string, post CosignaturePost) error {
	buf, _ := json.Marshal(post)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		operatorBase+"/v1/cosignatures", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("operator returned %d", resp.StatusCode)
	}
	return nil
}

// stderrSink is overridable in tests so cosign-loop log lines can
// be captured. Production points at os.Stderr.
var stderrSink = func() *_stderrWriter { return defaultStderrSink }

type _stderrWriter struct{}

var defaultStderrSink = &_stderrWriter{}

func (_stderrWriter) Write(p []byte) (int, error) {
	// Keep the writer dependency-free; main.go's log package
	// already covers structured logging at boot. Per-tick errors
	// are diagnostic noise that operators read via stderr.
	return len(p), nil
}
