package runner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/protocol"
	"github.com/baseproof/baseproof/types"

	libsbundle "github.com/baseproof/tooling/libs/bundle"
	"github.com/baseproof/tooling/libs/clitools"

	"github.com/baseproof/tooling/libs/networkbundle"
	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "federation.proof", Tags: []string{"proof", "verify"}, Run: federationProof})
}

// federation.proof: GENERATE a v2 self-anchored proof for a real committed entry
// over the live ledger, then VERIFY it fully OFFLINE with only the genesis trust
// root (VerifyStandalone makes zero network calls — the stack is irrelevant past
// the gather), and confirm the tamper matrix fails closed. This is the end-to-end
// acceptance of the proof generate→verify loop (epic baseproof#5, Waves 1–2).
func federationProof(s *Session) error {
	ctx := context.Background()
	n := intEnv("E2E_PROOF_ENTRIES", 16)
	// Works on single (1 network) AND federation (N) — every log is proven.
	return forEachNetwork(s, func(name string, t stack.Target) error {
		st, err := backfillDrained(t, s.Images.Ledger, n)
		if err != nil {
			return err
		}
		if len(st.Leaves) == 0 {
			return fmt.Errorf("backfill produced no SMT leaves")
		}
		// gather a v2 proof of a committed member, verify it offline, tamper it.
		return proveEntry(ctx, name, t, st.Leaves[0].Key)
	})
}

// forEachNetwork runs fn for every network in the persisted manifest — one on the
// `single` preset, N on `federation` — so a proof recipe validates EVERY log, not
// just the first. Fails on the first network's error, tagged with its name.
func forEachNetwork(s *Session, fn func(name string, t stack.Target) error) error {
	nets := s.Manifest.Networks
	if len(nets) == 0 {
		return fmt.Errorf("no network in the persisted manifest")
	}
	for _, nm := range nets {
		t, ok := s.Target(nm.Name)
		if !ok {
			return fmt.Errorf("no target for network %q", nm.Name)
		}
		if err := fn(nm.Name, t); err != nil {
			return fmt.Errorf("network %s: %w", nm.Name, err)
		}
	}
	return nil
}

// backfillDrained loads n entries and waits until the COMMITTED head reaches the
// ABSOLUTE size that includes them (size-before + roots) — robust on a reused stack,
// where a per-batch target (roots+1) is already satisfied and the wait would no-op,
// letting proveEntry race a not-yet-committed entry. proveEntry then polls the
// cosigned horizon the rest of the way (the witness-cosign lag).
func backfillDrained(t stack.Target, image string, n int) (*stack.BackfillStats, error) {
	before, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
	// Default to the original 8-worker, unbatched load; let big runs (300k+) raise
	// throughput via E2E_BACKFILL_WORKERS / E2E_BACKFILL_BATCH. Batching needs
	// credits admission (the only mode that batches) — fall back to unbatched on PoW.
	workers := intEnv("E2E_BACKFILL_WORKERS", 8)
	batch := intEnv("E2E_BACKFILL_BATCH", 1)
	if batch > 1 && t.Admission != "credits" {
		batch = 1
	}
	st, err := stack.Backfill(t, image, n, workers, 0.0, batch)
	if err != nil {
		return nil, err
	}
	target := before + st.Roots
	if !stack.WaitDrained(t.CertsDir, t.LedgerPort, target,
		time.Duration(intEnv("E2E_DRAIN_TIMEOUT_MIN", 15))*time.Minute) {
		return nil, fmt.Errorf("backfill did not drain to tree_size %d (raise E2E_DRAIN_TIMEOUT_MIN)", target)
	}
	return st, nil
}

// proveEntry gathers a v2 self-anchored proof of the member at leafKeyHex on
// network `name`/t via the BUNDLE-driven gather, verifies it FULLY OFFLINE with
// only the genesis trust root, and runs the tamper matrix (fail-closed: err==nil ⟺
// Valid). Shared by federation.proof and the federation.soak proof phase, so the
// deepest federated run also exercises the v2 proof generate→verify loop per
// network. The bundle carries the endpoint + trust root + vocabulary; a genesis-only
// network's complete proof is Part I + receipt + burn + witness short-circuit.
func proveEntry(ctx context.Context, name string, t stack.Target, leafKeyHex string) error {
	var key [32]byte
	kb, err := hex.DecodeString(leafKeyHex)
	if err != nil || len(kb) != 32 {
		return fmt.Errorf("%s: leaf key %q is not 32-byte hex", name, leafKeyHex)
	}
	copy(key[:], kb)

	doc, err := readBootstrapDoc(t)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	trustRoots, err := genesisTrustRoots(doc, t.QuorumK)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	baseURL := fmt.Sprintf("https://localhost:%d", t.LedgerPort)
	caFile := filepath.Join(t.CertsDir, "ca.crt")
	client, err := clitools.NewServerVerifyLedgerClient(baseURL, caFile, "localhost", t.LogDID)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	httpClient, err := caPinnedClient(caFile)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	// Resolve the entry's committed seq, POLLING the cosigned horizon until it
	// includes the entry. The witness-cosigned horizon (/v1/tree/horizon) lags the
	// committed head by a witness round, so a freshly backfilled entry resolves only
	// once cosigning catches up — a one-shot fetch races and reports non_membership on
	// a reused/persisted stack or under a fast loader. Robust at any scale.
	var seq uint64
	resolveDeadline := time.Now().Add(time.Duration(intEnv("E2E_RESOLVE_TIMEOUT_MIN", 5)) * time.Minute)
	for {
		hz, hErr := client.Horizon()
		if hErr == nil {
			if s, sErr := smtKeySeq(ctx, httpClient, baseURL, key, hz.SMTRoot); sErr == nil {
				seq = s
				break
			} else if time.Now().After(resolveDeadline) {
				return fmt.Errorf("%s: resolve seq for key %s (horizon never covered it): %w", name, short(leafKeyHex), sErr)
			}
		} else if time.Now().After(resolveDeadline) {
			return fmt.Errorf("%s: fetch horizon: %w", name, hErr)
		}
		time.Sleep(2 * time.Second)
	}

	nb, err := networkbundle.Build(doc, baseURL, networkbundle.Vocabulary{CitedMemberKey: key})
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	gather, err := libsbundle.NewBundleGather(ctx, nb, client, httpClient, seq, key)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	proof, err := sdkbundle.BuildStandalone(ctx, gather, seq)
	if err != nil {
		return fmt.Errorf("%s: BuildStandalone seq=%d: %w", name, seq, err)
	}

	res, err := sdkbundle.VerifyStandalone(ctx, proof, trustRoots)
	if err != nil || res == nil || !res.Valid {
		return fmt.Errorf("%s: offline verify FAILED: err=%v", name, err)
	}
	fmt.Printf("  [PASS] %-8s v2 proof seq=%d verified OFFLINE — coverage %v\n", name, seq, res.Coverage.Verified)

	if err := tamperRejected(ctx, proof, trustRoots); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	fmt.Printf("  [PASS] %-8s tamper matrix rejected (forged root_hash / smt_root / entry byte)\n", name)
	return nil
}

// tamperRejected confirms three independent forgeries each fail closed.
func tamperRejected(ctx context.Context, proof *sdkbundle.StandaloneProof, roots map[cosign.NetworkID]protocol.GenesisTrustRoot) error {
	cases := map[string]func(*sdkbundle.StandaloneProof){
		"forged root_hash": func(p *sdkbundle.StandaloneProof) { p.CosignedHead.RootHash[0] ^= 0xFF },
		"forged smt_root":  func(p *sdkbundle.StandaloneProof) { p.CosignedHead.SMTRoot[0] ^= 0xFF },
		"tampered entry":   func(p *sdkbundle.StandaloneProof) { p.Entry.WireBytes[0] ^= 0xFF },
	}
	for name, mut := range cases {
		bad := *proof
		bad.Entry.WireBytes = append([]byte(nil), proof.Entry.WireBytes...) // deep-copy the slice we mutate
		mut(&bad)
		res, err := sdkbundle.VerifyStandalone(ctx, &bad, roots)
		if err == nil || (res != nil && res.Valid) {
			return fmt.Errorf("tamper %q ACCEPTED — fail-closed contract broken", name)
		}
	}
	return nil
}

// readBootstrapDoc reads the network's genesis bootstrap document (minted by
// MintBootstrap into the fixtures dir).
func readBootstrapDoc(t stack.Target) (*network.BootstrapDocument, error) {
	raw, err := os.ReadFile(filepath.Join(t.FixturesDir, "network-bootstrap.json"))
	if err != nil {
		return nil, fmt.Errorf("read bootstrap: %w", err)
	}
	var doc network.BootstrapDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode bootstrap: %w", err)
	}
	return &doc, nil
}

// genesisTrustRoots derives the single-network trust root from the bootstrap
// document — exactly the external input VerifyStandalone binds against (D1).
func genesisTrustRoots(doc *network.BootstrapDocument, quorumK int) (map[cosign.NetworkID]protocol.GenesisTrustRoot, error) {
	ids, err := doc.IDs()
	if err != nil {
		return nil, fmt.Errorf("bootstrap IDs: %w", err)
	}
	canonical, err := doc.CanonicalBytes()
	if err != nil {
		return nil, fmt.Errorf("bootstrap canonical bytes: %w", err)
	}
	nid := cosign.NetworkID(ids.NetworkID)
	return map[cosign.NetworkID]protocol.GenesisTrustRoot{
		nid: {
			NetworkID:             nid,
			GenesisWitnessDIDs:    append([]string(nil), doc.GenesisWitnessSet...),
			QuorumK:               quorumK,
			BootstrapDocumentHash: sha256.Sum256(canonical),
		},
	}, nil
}

// smtKeySeq fetches the entry's SMT membership proof and reads its committed seq
// off the terminal leaf (OriginTip, else AuthorityTip).
func smtKeySeq(ctx context.Context, httpClient *http.Client, baseURL string, key, smtRoot [32]byte) (uint64, error) {
	url := fmt.Sprintf("%s/v1/smt/proof/%s?smt_root=%s",
		baseURL, hex.EncodeToString(key[:]), hex.EncodeToString(smtRoot[:]))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return 0, err
	}
	var body struct {
		Type  string         `json:"type"`
		Proof types.SMTProof `json:"proof"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return 0, err
	}
	if body.Type != "membership" || body.Proof.TerminalLeaf == nil {
		return 0, fmt.Errorf("entry not present at key (type=%q)", body.Type)
	}
	leaf := body.Proof.TerminalLeaf
	if !leaf.OriginTip.IsNull() {
		return leaf.OriginTip.Sequence, nil
	}
	if !leaf.AuthorityTip.IsNull() {
		return leaf.AuthorityTip.Sequence, nil
	}
	return 0, fmt.Errorf("SMT leaf has no committed position")
}

// caPinnedClient builds an HTTPS client that verifies the ledger's self-signed
// server cert against the run CA (ServerName localhost) — the same posture the
// e2e tools use (open read, no client cert).
func caPinnedClient(caFile string) (*http.Client, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA %s has no certificates", caFile)
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"},
		},
	}, nil
}
