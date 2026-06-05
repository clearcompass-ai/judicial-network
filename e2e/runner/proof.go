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

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
	"github.com/clearcompass-ai/judicial-network/networkbundle"
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
	t, ok := s.Target("")
	if !ok {
		return fmt.Errorf("no network in the persisted manifest")
	}
	ctx := context.Background()

	// 1. A workload so the SMT carries member keys and the head is witness-cosigned.
	n := intEnv("E2E_PROOF_ENTRIES", 16)
	st, err := stack.Backfill(t, s.Images.Ledger, n, 8, 0.0, 1)
	if err != nil {
		return err
	}
	if len(st.Leaves) == 0 {
		return fmt.Errorf("backfill produced no SMT leaves")
	}
	if !stack.WaitDrained(t.CertsDir, t.LedgerPort, st.Roots+1, // +1 for the genesis seed
		time.Duration(intEnv("E2E_DRAIN_TIMEOUT_MIN", 15))*time.Minute) {
		return fmt.Errorf("builder did not drain the backfill (raise E2E_DRAIN_TIMEOUT_MIN)")
	}

	// 2. The genesis trust root — the ONLY external input the offline verifier needs.
	doc, err := readBootstrapDoc(t)
	if err != nil {
		return err
	}
	trustRoots, err := genesisTrustRoots(doc, t.QuorumK)
	if err != nil {
		return err
	}

	// 3. The ledger read clients: server-verify against the run CA, NO client cert
	//    (the ledger serves reads openly; writes gate on in-body crypto).
	baseURL := fmt.Sprintf("https://localhost:%d", t.LedgerPort)
	caFile := filepath.Join(t.CertsDir, "ca.crt")
	client, err := clitools.NewServerVerifyLedgerClient(baseURL, caFile, "localhost", t.LogDID)
	if err != nil {
		return err
	}
	httpClient, err := caPinnedClient(caFile)
	if err != nil {
		return err
	}

	// 4. Pick a target SMT-committed entry; resolve its seq from the SMT leaf
	//    (OriginTip), so we have the (seq, key) pair the gather needs.
	var key [32]byte
	kb, err := hex.DecodeString(st.Leaves[0].Key)
	if err != nil || len(kb) != 32 {
		return fmt.Errorf("oracle leaf key %q is not 32-byte hex", st.Leaves[0].Key)
	}
	copy(key[:], kb)
	hz, err := client.Horizon()
	if err != nil {
		return fmt.Errorf("fetch horizon: %w", err)
	}
	seq, err := smtKeySeq(ctx, httpClient, baseURL, key, hz.SMTRoot)
	if err != nil {
		return fmt.Errorf("resolve seq for key %s: %w", short(st.Leaves[0].Key), err)
	}

	// 5. GATHER the proof via the network BUNDLE — the single per-network object
	//    (endpoint + trust root + vocabulary) the gather drives. The bundle fetches
	//    the genesis bootstrap from the endpoint and hash-verifies it against its
	//    pin. A genesis-only network carries no governance/signer vocabulary, so its
	//    complete proof is Part I + receipt + burn + witness short-circuit; the
	//    bundle-driven path is exercised regardless. CitedMemberKey names a real
	//    committed member (the federation citation target).
	nb, err := networkbundle.Build(doc, baseURL, t.QuorumK, networkbundle.Vocabulary{CitedMemberKey: key})
	if err != nil {
		return err
	}
	gather, err := libsbundle.NewBundleGather(ctx, nb, client, httpClient, seq, key)
	if err != nil {
		return err
	}
	proof, err := sdkbundle.BuildStandalone(ctx, gather, seq)
	if err != nil {
		return fmt.Errorf("BuildStandalone seq=%d: %w", seq, err)
	}

	// 6. VERIFY OFFLINE. VerifyStandalone consults only (proof, trustRoots) + SHA-256
	//    — no ledger, no network. A green verdict here would hold with the stack down.
	res, err := sdkbundle.VerifyStandalone(ctx, proof, trustRoots)
	if err != nil || res == nil || !res.Valid {
		return fmt.Errorf("offline verify FAILED: err=%v", err)
	}
	fmt.Printf("  [PASS] proof seq=%d verified OFFLINE — coverage %v\n", seq, res.Coverage.Verified)

	// 7. TAMPER MATRIX (fail-closed contract: err==nil ⟺ Valid). Each forgery must
	//    invalidate the proof.
	if err := tamperRejected(ctx, proof, trustRoots); err != nil {
		return err
	}
	fmt.Println("  [PASS] tamper matrix rejected (forged root_hash / smt_root / entry byte)")
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
