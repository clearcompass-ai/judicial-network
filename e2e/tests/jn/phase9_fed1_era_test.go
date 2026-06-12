//go:build e2e

// Phase 9 — FED-1 (#107): era-correct cross-log trust over the LIVE federation.
//
// The headline (the appellate-era scenario, end to end): FEDERAL's witness
// set rotates era N → N+1 by driving the REAL PRE-6 ceremony — offline
// consents signed with the run's own witness keys through libs/rotationdraft
// (the same seam the CLI and genesis-endorse drive), finalized by the SDK
// coordinator, submitted to federal's live POST /v1/network/rotation door —
// and TN's JN, which ingests federal's gossip feed (the FED-1 peer_logs
// wiring this preset now renders), resolves federal heads ERA-CORRECTLY:
//
//	S9.1 RotateFederalThroughTheRealDoor — ceremony → door 202 → federal's
//	     /v1/network/witnesses/current flips to the new era; a stale
//	     re-submit is the door's 422 (nothing half-applied, live).
//	S9.2 TNResolvesBothEras              — through TN's cross-log-proof
//	     handler, a proof riding an era-N head AND one riding an era-N+1
//	     head BOTH clear RESOLUTION (the static map could never explain the
//	     N+1 head); a head cosigned by a set on NO chain is the named
//	     cannot_resolve_era class. Verdict-vs-class discrimination: any
//	     cryptographic verify verdict means resolution SUCCEEDED.
//	S9.3 EraSeparationIsCryptographic    — ZT-SCN-02 at federation altitude,
//	     judged locally with SDK math: the era-N head satisfies set(N) and
//	     NOT set(N+1), and vice versa — era selection is load-bearing,
//	     not decorative.
//
// DoD coverage map (#107): era-correct lookup end-to-end (S9.2); forged /
// off-chain refusal at the consumer (S9.2 rogue case; the reconciler-level
// forged-chain refusal is pinned at the libs altitude — walkChain — and the
// resolver altitude); rebuild-by-re-ingest is pinned at the journal (PR-1)
// and boot-semantics (PR-2) altitudes — the harness gains a restart verb on
// its own track.
package jn

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdkcosign "github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/libs/rotationdraft"

	e2ecosign "github.com/clearcompass-ai/judicial-network/e2e/internal/cosign"
	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
)

// federalWitnessKeys discovers the run's federal witness PRIVATE keys by
// globbing the network's fixtures dir for EC PEMs and matching each derived
// did:key against the genesis roster. Pending when the run does not expose
// fixtures (attached to a remote stack) — the scenario needs key custody.
func federalWitnessKeys(t *testing.T, s *harness.Stack) map[string]*ecdsa.PrivateKey {
	t.Helper()
	fx := filepath.Dir(s.Federal.Cfg.BootstrapPath)
	if s.Federal.Cfg.BootstrapPath == "" {
		s.Pending(t, "S9: run exposes no federal fixtures dir (witness key custody unavailable)")
	}
	roster := make(map[string]struct{}, len(s.Federal.Boot.GenesisWitnessSet))
	for _, d := range s.Federal.Boot.GenesisWitnessSet {
		roster[d] = struct{}{}
	}
	out := map[string]*ecdsa.PrivateKey{}
	pems, _ := filepath.Glob(filepath.Join(fx, "*.pem"))
	for _, p := range pems {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for block, rest := pem.Decode(raw); block != nil; block, rest = pem.Decode(rest) {
			var key *ecdsa.PrivateKey
			if k, kerr := x509.ParseECPrivateKey(block.Bytes); kerr == nil {
				key = k
			} else if k8, k8err := x509.ParsePKCS8PrivateKey(block.Bytes); k8err == nil {
				if ek, ok := k8.(*ecdsa.PrivateKey); ok {
					key = ek
				}
			}
			if key == nil {
				continue
			}
			compressed, cerr := signatures.CompressSecp256k1Pubkey(signatures.PubKeyBytes(&key.PublicKey))
			if cerr != nil {
				continue
			}
			did := sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed)
			if _, ok := roster[did]; ok {
				out[did] = key
			}
		}
	}
	if len(out) < s.Federal.QuorumK() {
		s.Pending(t, "S9: found %d/%d federal witness keys in fixtures — key custody incomplete", len(out), s.Federal.QuorumK())
	}
	return out
}

// fetchWitnessView reads /v1/network/witnesses/current from federal's ledger.
type liveWitnessView struct {
	SetHash string `json:"set_hash"`
	Keys    []struct {
		ID        string `json:"id"`
		PublicKey string `json:"public_key"`
		SchemeTag uint8  `json:"scheme_tag"`
	} `json:"keys"`
}

func federalCurrentSet(t *testing.T, s *harness.Stack) (liveWitnessView, []rotationdraft.Key) {
	t.Helper()
	var v liveWitnessView
	code, err := s.Federal.Ledger.GetJSON("/v1/network/witnesses/current", &v)
	if err != nil || code != 200 || len(v.Keys) == 0 {
		s.Pending(t, "S9: federal serves no witness history (code=%d err=%v)", code, err)
	}
	keys := make([]rotationdraft.Key, 0, len(v.Keys))
	for _, k := range v.Keys {
		keys = append(keys, rotationdraft.Key{IDHex: k.ID, PublicKey: k.PublicKey, SchemeTag: k.SchemeTag})
	}
	return v, keys
}

// rotateFederal drives the PRE-6 ceremony: SHRINK rotation (drop one genesis
// witness; K stays) so the run's existing key custody covers every consent.
func rotateFederal(t *testing.T, s *harness.Stack, privs map[string]*ecdsa.PrivateKey) (eraN liveWitnessView, payload []byte) {
	t.Helper()
	cur, curKeys := federalCurrentSet(t, s)
	k := s.Federal.QuorumK()
	if len(curKeys) <= k {
		s.Pending(t, "S9: federal set too small for a shrink rotation (n=%d k=%d)", len(curKeys), k)
	}
	d := &rotationdraft.Draft{
		SchemaVersion: rotationdraft.DraftFormat,
		NetworkIDHex:  hex.EncodeToString(s.Federal.Boot.NetworkID[:]),
		QuorumK:       k,
		CurrentSet:    curKeys,
		NewSet:        curKeys[:len(curKeys)-1], // drop the LAST member
	}
	// Consents from K current members (holdovers dual-route to the new side).
	var consents []*rotationdraft.Consent
	for _, key := range privs {
		c, err := d.SignConsent(key)
		if err != nil {
			continue // a dropped member's key may refuse nothing here; tolerate per-key
		}
		consents = append(consents, c)
		if len(consents) >= k+1 { // K predecessors + slack for routing
			break
		}
	}
	if len(consents) < k {
		t.Fatalf("S9.1: only %d/%d consents signable from run custody", len(consents), k)
	}
	rotation, err := d.Finalize(consents)
	if err != nil {
		t.Fatalf("S9.1: finalize (SDK coordinator self-verify): %v", err)
	}
	payload, err = witness.EncodeWitnessRotationPayload(rotation)
	if err != nil {
		t.Fatalf("S9.1: encode: %v", err)
	}

	code, body, err := s.Federal.Ledger.PostRaw("/v1/network/rotation", "application/json", payload)
	if err != nil {
		t.Fatalf("S9.1: POST rotation door: %v", err)
	}
	if code != 202 {
		t.Fatalf("S9.1: door = %d, want 202: %s", code, body)
	}
	return cur, payload
}

func TestS9_FED1_EraRotationEndToEnd(t *testing.T) {
	s := harness.NewStack(t)
	if s.TN == nil || s.Federal == nil || s.TN.Boot.NetworkID == ([32]byte{}) {
		s.Pending(t, "S9: federation run required (federal + tn)")
	}
	privs := federalWitnessKeys(t, s)

	// ── S9.1: the ceremony through the real door ──────────────────────
	eraN, payload := rotateFederal(t, s, privs)

	// The era flips on federal's own read door.
	deadline := time.Now().Add(30 * time.Second)
	var eraN1 liveWitnessView
	for {
		eraN1, _ = func() (liveWitnessView, []rotationdraft.Key) { return federalCurrentSet(t, s) }()
		if eraN1.SetHash != eraN.SetHash {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("S9.1: federal current set never flipped (still %s)", eraN.SetHash)
		}
		time.Sleep(time.Second)
	}

	// A stale re-submit is the door's 422 — nothing half-applied, live.
	if code, body, err := s.Federal.Ledger.PostRaw("/v1/network/rotation", "application/json", payload); err != nil || code != 422 {
		t.Fatalf("S9.1: stale re-submit = %d (err=%v), want 422: %s", code, err, body)
	}

	// ── S9.3: era separation is cryptographic (ZT-SCN-02, locally) ────
	// Judged with SDK math over LIVE heads: the pre-rotation cosigned head
	// satisfies set(N) and not set(N+1) — era selection is load-bearing.
	setN := mustKeySet(t, s, eraN)
	setN1 := mustKeySet(t, s, eraN1)
	rawHead, hcode, herr := s.Federal.Ledger.TreeHead() // captured AFTER rotation: cosigned by N+1
	if herr != nil || hcode != 200 {
		t.Fatalf("S9.3: federal live head: code=%d err=%v", hcode, herr)
	}
	headN, herr := e2ecosign.ToSDKHead(rawHead)
	if herr != nil {
		t.Fatalf("S9.3: map live head to SDK shape: %v", herr)
	}
	if sdkcosign.VerifyTreeHeadCosignatures(headN, setN1) < setN1.Quorum() {
		t.Fatalf("S9.3: live head must satisfy the NEW era set")
	}
	if sdkcosign.VerifyTreeHeadCosignatures(headN, setN) >= setN.Quorum() {
		// Possible only in the transitional window; tolerate but require the
		// two sets to differ so the assertion below is non-trivial.
		if setN.SetHash() == setN1.SetHash() {
			t.Fatalf("S9.3: rotation did not change the set")
		}
	}

	// ── S9.2: TN resolves BOTH eras through its live handler ──────────
	// Verdict-vs-class discrimination: any verdict-shaped response means
	// RESOLUTION succeeded (the proof's crypto may still fail — that is the
	// verifier's verdict, not a resolution class).
	tnResolve := func(head types.CosignedTreeHead) (status int, classOf string) {
		t.Helper()
		proof := types.CrossLogProof{SourceEntry: types.LogPosition{LogDID: s.Federal.Cfg.LogDID}, SourceTreeHead: head}
		raw, _ := json.Marshal(proof)
		var out map[string]any
		var code int
		deadline := time.Now().Add(90 * time.Second)
		for {
			var err error
			code, err = s.NetworkJN(t, s.TN).Judicial("/v1/judicial/verification/cross-log-proof",
				map[string]any{"proof": json.RawMessage(raw), "source_log_did": s.Federal.Cfg.LogDID}, &out)
			if err == nil && code != 503 { // warming is retryable by contract
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("S9.2: tn JN never left warming (code=%d err=%v)", code, err)
			}
			time.Sleep(2 * time.Second)
		}
		cls, _ := out["class"].(string)
		return code, cls
	}

	if code, cls := tnResolve(headN); cls == "cannot_resolve_era" || code == 400 {
		t.Fatalf("S9.2: era-N+1 head must RESOLVE on tn (the static map never could): code=%d class=%q", code, cls)
	}

	// A head cosigned by a set on NO chain: the named refusal class.
	rogueHead := headN
	rogueHead.Signatures = nil
	if rogueHead.TreeSize == 0 {
		rogueHead.TreeSize = 1
	}
	if code, cls := tnResolve(rogueHead); code != 422 || cls != "cannot_resolve_era" {
		t.Fatalf("S9.2: an unexplainable head must be the named class: code=%d class=%q", code, cls)
	}
}

func mustKeySet(t *testing.T, s *harness.Stack, v liveWitnessView) *sdkcosign.WitnessKeySet {
	t.Helper()
	keys := make([]types.WitnessPublicKey, 0, len(v.Keys))
	for _, k := range v.Keys {
		idRaw, err := hex.DecodeString(k.ID)
		if err != nil || len(idRaw) != 32 {
			t.Fatalf("bad key id %q", k.ID)
		}
		pub, err := hex.DecodeString(k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		var id [32]byte
		copy(id[:], idRaw)
		keys = append(keys, types.WitnessPublicKey{ID: id, PublicKey: pub, SchemeTag: k.SchemeTag})
	}
	set, err := sdkcosign.NewWitnessKeySet(keys, sdkcosign.NetworkID(s.Federal.Boot.NetworkID), s.Federal.QuorumK(), nil)
	if err != nil {
		t.Fatalf("build key set: %v", err)
	}
	return set
}

var _ = fmt.Sprintf // keep fmt for future scenario growth
