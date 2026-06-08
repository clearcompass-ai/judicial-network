package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	libsbundle "github.com/baseproof/tooling/libs/bundle"
	"github.com/baseproof/tooling/libs/clitools"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
	"github.com/clearcompass-ai/judicial-network/networkbundle"
)

func init() {
	Register(Recipe{Name: "federation.shadow.debug", Tags: []string{"federation", "shadow", "debug", "verify"}, Run: federationShadowDebug})
}

// federation.shadow.debug — the EXHAUSTIVELY INSTRUMENTED twin of federation.shadow.
// It proves the SAME committed entry against the PG-backed writer (known-good
// baseline) AND the PG-off, object-store-backed reader, but narrates every layer:
//
//   - every HTTP hop is logged by a tracing RoundTripper (method, host:port, path,
//     status, latency) — including the 302 → object-store byte fetch — so a stall or
//     non-2xx is pinned to the exact request, never inferred;
//   - an explicit endpoint SWEEP hits every surface the v2 proof depends on
//     (horizon, smt/root, checkpoint, inclusion, entry, receipt, burn, raw), on BOTH
//     nodes, and flags the two routes the SDK gather treats as FATAL if absent
//     (/v1/receipt/proof, /v1/burn);
//   - then the REAL gather → BuildStandalone → VerifyStandalone runs, so a section
//     that the sweep showed 404 is shown failing the build at the exact section.
//
// Targets ONE network (E2E_DEBUG_NETWORK, else the first). The reader port is
// E2E_READER_PORT (else the manifest's ReaderPort, else :8081) — so it works against
// a hand-launched reader even when the persisted manifest carries ReaderPort=0.
//
// This recipe never hangs silently: the resolve poll is capped at
// E2E_RESOLVE_TIMEOUT_MIN (default 1 here, not 5) so a missing surface surfaces fast.
func federationShadowDebug(s *Session) error {
	ctx := context.Background()
	if len(s.Manifest.Networks) == 0 {
		return fmt.Errorf("no network in the persisted manifest — `e2e up` first")
	}
	name := os.Getenv("E2E_DEBUG_NETWORK")
	if name == "" {
		name = s.Manifest.Networks[0].Name
	}
	t, ok := s.Target(name)
	if !ok {
		return fmt.Errorf("no target for network %q", name)
	}
	readerPort := intEnv("E2E_READER_PORT", t.ReaderPort)
	if readerPort == 0 {
		readerPort = 8081
	}
	n := intEnv("E2E_SHADOW_ENTRIES", 8)

	fmt.Printf("== shadow.debug  network=%s  writer=:%d  reader=:%d  entries=%d ==\n",
		name, t.LedgerPort, readerPort, n)

	// Workload on the WRITER → committed + shipped to the object store the reader serves.
	before, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
	st, err := stack.Backfill(t, s.Images.Ledger, n, intEnv("E2E_BACKFILL_WORKERS", 8), 0.0, intEnv("E2E_BACKFILL_BATCH", 1))
	if err != nil {
		return fmt.Errorf("backfill: %w", err)
	}
	if !stack.WaitDrained(t.CertsDir, t.LedgerPort, before+st.Roots,
		time.Duration(intEnv("E2E_DRAIN_TIMEOUT_MIN", 15))*time.Minute) {
		return fmt.Errorf("backfill did not drain")
	}
	if len(st.Leaves) == 0 {
		return fmt.Errorf("backfill produced no SMT leaves")
	}
	var key [32]byte
	kb, err := hex.DecodeString(st.Leaves[0].Key)
	if err != nil || len(kb) != 32 {
		return fmt.Errorf("committed leaf key %q is not 32-byte hex", st.Leaves[0].Key)
	}
	copy(key[:], kb)
	fmt.Printf("   committed leaf key = %s\n\n", st.Leaves[0].Key)

	fmt.Println("──────────── WRITER (PG-backed baseline) ────────────")
	wErr := instrumentedProve(ctx, "writer", t, t.LedgerPort, key)
	fmt.Println("\n──────────── READER (PG-off, object-store-backed) ────────────")
	rErr := instrumentedProve(ctx, "reader", t, readerPort, key)

	fmt.Printf("\n== verdict: writer=%s  reader=%s ==\n", passFail(wErr), passFail(rErr))
	switch {
	case wErr != nil && rErr != nil:
		return fmt.Errorf("BOTH failed — writer baseline is broken: writer=%v · reader=%v", wErr, rErr)
	case rErr != nil:
		return fmt.Errorf("reader proof failed (writer baseline PASSED): %v", rErr)
	case wErr != nil:
		return fmt.Errorf("writer baseline failed: %v", wErr)
	}
	return nil
}

// instrumentedProve reproduces proof.go's proveEntry against one node (writer or
// reader) with full per-step + per-hop instrumentation, then runs the real
// BuildStandalone/VerifyStandalone so any object-store gap fails at the exact section.
func instrumentedProve(ctx context.Context, label string, t stack.Target, port int, key [32]byte) error {
	say := func(format string, a ...any) { fmt.Printf("    %-6s │ "+format+"\n", append([]any{label}, a...)...) }
	baseURL := fmt.Sprintf("https://localhost:%d", port)
	caFile := filepath.Join(t.CertsDir, "ca.crt")
	say("target %s  (CA %s)", baseURL, caFile)

	// CA-pinned client with a tracing transport: every hop on THIS client (smt proof,
	// receipt, burn, discovery, and the explicit sweep) is logged. clitools' own client
	// (horizon, inclusion, entry /raw, scan) is not injectable, so the sweep probes those
	// endpoints explicitly too — nothing is invisible.
	base, err := caPinnedClient(caFile)
	if err != nil {
		say("✗ CA-pinned client: %v", err)
		return err
	}
	hc := &http.Client{Timeout: base.Timeout, Transport: &tracingRT{inner: base.Transport, label: label}}
	noFollow := &http.Client{Timeout: base.Timeout, Transport: hc.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	doc, err := readBootstrapDoc(t)
	if err != nil {
		say("✗ bootstrap doc: %v", err)
		return err
	}
	trustRoots, err := genesisTrustRoots(doc, t.QuorumK)
	if err != nil {
		say("✗ genesis trust roots: %v", err)
		return err
	}
	client, err := clitools.NewServerVerifyLedgerClient(baseURL, caFile, "localhost", t.LogDID)
	if err != nil {
		say("✗ ledger client: %v", err)
		return err
	}

	// ── horizon (clitools' own client) ───────────────────────────────────────
	t0 := time.Now()
	hz, err := client.Horizon()
	if err != nil {
		say("✗ horizon: %v  (%s)", err, since(t0))
		code, _, snip := getProbe(ctx, hc, baseURL+"/v1/tree/horizon")
		say("  ↳ raw /v1/tree/horizon → %d %s", code, snip)
		return err
	}
	say("✓ horizon: tree_size=%d smt_root=%s… root_hash=%s…  (%s)",
		hz.TreeSize, hex.EncodeToString(hz.SMTRoot[:])[:12], hex.EncodeToString(hz.RootHash[:])[:12], since(t0))

	// ── key → seq via /v1/smt/proof (my traced client) ───────────────────────
	t0 = time.Now()
	seq, err := smtKeySeq(ctx, hc, baseURL, key, hz.SMTRoot)
	if err != nil {
		say("✗ smtKeySeq (the exact poll-loop call): %v  (%s)", err, since(t0))
		return err
	}
	say("✓ smtKeySeq: key→seq=%d  (%s)", seq, since(t0))

	// ── explicit endpoint sweep: every surface the v2 proof depends on ────────
	sweep := func(tagName, url string) int {
		s0 := time.Now()
		code, n, snip := getProbe(ctx, hc, url)
		mark := "✓"
		if code < 200 || code >= 300 {
			mark = "✗"
		}
		say("%s %-20s → %d (%dB, %s) %s", mark, tagName, code, n, since(s0), snip)
		return code
	}
	sweep("tree/head", baseURL+"/v1/tree/head")
	sweep("smt/root", baseURL+"/v1/smt/root")
	sweep("tree/checkpoint", fmt.Sprintf("%s/v1/tree/checkpoint/%d", baseURL, hz.TreeSize))
	sweep("tree/inclusion", fmt.Sprintf("%s/v1/tree/inclusion/%d?tree_size=%d", baseURL, seq, hz.TreeSize))
	sweep("entries/{seq}", fmt.Sprintf("%s/v1/entries/%d", baseURL, seq))
	receiptCode := sweep("receipt/proof", fmt.Sprintf("%s/v1/receipt/proof/%d", baseURL, seq))
	burnCode := sweep("burn", baseURL+"/v1/burn")

	// raw entry: capture the 302 Location, fetch the bytes from the object store,
	// and verify sha256(bytes) == the hash the redirect path names (the /raw contract).
	loc, blen, bsum, rawCode := rawEntryProbe(ctx, noFollow, hc, baseURL, seq)
	if rawCode == http.StatusFound && loc != "" {
		want := loc[strings.LastIndex(loc, "/")+1:]
		say("✓ entries/%d/raw     → 302; fetched %dB sha256=%s… hash-match=%v", seq, blen, firstN(bsum, 12), strings.EqualFold(want, bsum))
	} else {
		say("✗ entries/%d/raw     → %d loc=%q", seq, rawCode, loc)
	}

	// Flag the two SDK-FATAL gaps explicitly (server.go mounts these routes only when
	// the handler is non-nil; the gather errors out on a non-200 from either).
	if receiptCode == http.StatusNotFound {
		say("‼ /v1/receipt/proof is NOT mounted (404) — BuildStandalone WILL fail on the receipt_proof section")
	}
	if burnCode == http.StatusNotFound {
		say("‼ /v1/burn is NOT mounted (404) — BuildStandalone WILL fail on the burn_attestation section")
	}

	// ── the real gather → BuildStandalone → VerifyStandalone ──────────────────
	nb, err := networkbundle.Build(doc, baseURL, t.QuorumK, networkbundle.Vocabulary{CitedMemberKey: key})
	if err != nil {
		say("✗ networkbundle.Build: %v", err)
		return err
	}
	gather, err := libsbundle.NewBundleGather(ctx, nb, client, hc, seq, key)
	if err != nil {
		say("✗ NewBundleGather: %v", err)
		return err
	}
	t0 = time.Now()
	proof, err := sdkbundle.BuildStandalone(ctx, gather, seq)
	if err != nil {
		say("✗ BuildStandalone seq=%d: %v  (%s)", seq, err, since(t0))
		return err
	}
	say("✓ BuildStandalone seq=%d  (%s)", seq, since(t0))

	t0 = time.Now()
	res, err := sdkbundle.VerifyStandalone(ctx, proof, trustRoots)
	if err != nil || res == nil || !res.Valid {
		say("✗ VerifyStandalone: valid=%v err=%v  (%s)", res != nil && res.Valid, err, since(t0))
		return fmt.Errorf("offline verify failed")
	}
	say("✓ VerifyStandalone OFFLINE  (%s)  coverage=%+v", since(t0), res.Coverage)

	if err := tamperRejected(ctx, proof, trustRoots); err != nil {
		say("✗ tamper matrix: %v", err)
		return err
	}
	say("✓ tamper matrix rejected (forged root_hash / smt_root / entry byte)")
	return nil
}

// tracingRT logs every HTTP round-trip the instrumented proof makes on its client —
// method, host:port, path+query, status (or transport error), and latency — so a
// stall or non-2xx is pinned to the exact request, including the 302→object-store hop.
type tracingRT struct {
	inner http.RoundTripper
	label string
}

func (rt *tracingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := rt.inner.RoundTrip(req)
	d := since(start)
	if err != nil {
		fmt.Printf("        ⟂ %-6s %s %s%s → ERR %v (%s)\n", rt.label, req.Method, req.URL.Host, req.URL.RequestURI(), err, d)
		return resp, err
	}
	fmt.Printf("        ⟂ %-6s %s %s%s → %d (%s)\n", rt.label, req.Method, req.URL.Host, req.URL.RequestURI(), resp.StatusCode, d)
	return resp, err
}

// getProbe GETs url over hc, drains the body (bounded), and returns the status, the
// byte count, and — on a non-2xx — a trimmed snippet of the error body.
func getProbe(ctx context.Context, hc *http.Client, url string) (code, size int, snippet string) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, 0, "(" + err.Error() + ")"
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet = strings.TrimSpace(string(b))
		snippet = firstN(snippet, 140)
	}
	return resp.StatusCode, len(b), snippet
}

// rawEntryProbe hits /v1/entries/{seq}/raw WITHOUT following the redirect (to capture
// the 302 Location), then fetches the named object and returns its length + sha256 —
// the host-side analog of a verifier following the ledger's redirect to the bytestore.
func rawEntryProbe(ctx context.Context, noFollow, hc *http.Client, baseURL string, seq uint64) (loc string, n int, sum string, code int) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/v1/entries/%d/raw", baseURL, seq), nil)
	resp, err := noFollow.Do(req)
	if err != nil {
		return "", 0, "", 0
	}
	code = resp.StatusCode
	loc = resp.Header.Get("Location")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if loc == "" {
		return loc, 0, "", code
	}
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
	r2, err := hc.Do(req2)
	if err != nil {
		return loc, 0, "", code
	}
	defer func() { _ = r2.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(r2.Body, 16<<20))
	s := sha256.Sum256(body)
	return loc, len(body), hex.EncodeToString(s[:]), code
}

func since(t0 time.Time) time.Duration { return time.Since(t0).Round(time.Millisecond) }

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func passFail(err error) string {
	if err == nil {
		return "PASS"
	}
	return "FAIL"
}
