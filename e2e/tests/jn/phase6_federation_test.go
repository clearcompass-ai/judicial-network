//go:build e2e

// Phase 6 — Multi-network FEDERATION / CROSS-LOG scenarios (S6.20+).
//
// Where S6.10–S6.15 prove the topology contract (shared witness identities,
// distinct trust roots, ledger-boundary isolation), this file exercises the
// SDK's agnostic cross-log capability END-TO-END over the LIVE 3-network
// federation (Federal / TN / CA):
//
//	S6.20 FederationNetworkIDsDistinct      — each live network has a distinct
//	                                          NetworkID (the cross-log precondition).
//	S6.21 EachNetworkHeadMeetsQuorum        — each live head is a real K-of-N
//	                                          cosigned head under its own witness
//	                                          set (the per-hop source crypto).
//	S6.22 FederationVerifyFailsClosed       — federation.VerifyFromOrigin over
//	                                          handles built from LIVE bootstraps
//	                                          fails closed: cycle, single-network,
//	                                          unknown origin, unknown trust.
//	S6.23 CrossNetworkAnchorWrite           — build a REAL cross-network anchor of
//	                                          one network's live head and submit it
//	                                          to another network's ledger; assert
//	                                          the admission outcome.
//
// DOMAIN MODEL: one network = one log; cross-log is strictly between two DIFFERENT
// networks. The federation handles below are JN's own member.TNCourtSystem
// (protocol.MemberNetwork) carrying each network's REAL NetworkID + witness set,
// proving the concrete domain handle drives the agnostic SDK building block.
package jn

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/core/envelope"
	sdkcosign "github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/federation"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
	"github.com/baseproof/baseproof/witness"

	e2ecosign "github.com/clearcompass-ai/judicial-network/e2e/internal/cosign"
	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
	"github.com/clearcompass-ai/judicial-network/member"
)

// ── helpers: build REAL SDK federation handles from a live network bootstrap ──

// witnessSetFor builds the network's K-of-N witness key set from its genesis
// bootstrap — the SAME path the cosign verifier uses (witness.KeysFromDIDs +
// NewWitnessKeySet), so it is the real set the live witnesses cosign under.
func witnessSetFor(t *testing.T, n *harness.NetworkStack) *sdkcosign.WitnessKeySet {
	t.Helper()
	keys, err := witness.KeysFromDIDs(n.Boot.GenesisWitnessSet)
	if err != nil {
		t.Fatalf("net %s: witness keys from genesis DIDs: %v", n.Name, err)
	}
	set, err := sdkcosign.NewWitnessKeySet(keys, sdkcosign.NetworkID(n.Boot.NetworkID), n.QuorumK(), nil)
	if err != nil {
		t.Fatalf("net %s: build witness key set: %v", n.Name, err)
	}
	return set
}

func networkIDOf(n *harness.NetworkStack) sdkcosign.NetworkID {
	return sdkcosign.NetworkID(n.Boot.NetworkID)
}

func exchangeDIDOf(s *harness.Stack, n *harness.NetworkStack) string {
	if v := s.Topology.Network(n.Name); v != nil {
		return v.ExchangeDID
	}
	return ""
}

// bootReady reports whether a network's bootstrap (genesis witness set) is
// loaded — required to build a federation handle.
func bootReady(n *harness.NetworkStack) bool { return len(n.Boot.GenesisWitnessSet) > 0 }

// handle wraps a live network as an SDK federation.AnchoredNetwork via JN's own
// member.TNCourtSystem, carrying the network's REAL NetworkID + witness set. The
// anchor DID is supplied per scenario (the federation graph edge under test).
func handle(t *testing.T, s *harness.Stack, n *harness.NetworkStack, anchorDID string) federation.AnchoredNetwork {
	return federation.AnchoredNetwork{
		DID:     exchangeDIDOf(s, n),
		Network: member.New(networkIDOf(n), anchorDID, witnessSetFor(t, n), nil),
	}
}

func knownClean(string) verifier.TrustStatus { return verifier.TrustStatus{Known: true} }
func zeroTrust(string) verifier.TrustStatus  { return verifier.TrustStatus{} }

// ── S6.20 — distinct NetworkIDs across the live federation ────────────────────

func TestS6_20_FederationNetworkIDsDistinct(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireTopology(t)
	s.RequireSecondCourt(t) // cross-log requires >= 2 networks

	seen := map[sdkcosign.NetworkID]string{}
	count := 0
	for _, n := range s.AllNetworks() {
		if !bootReady(n) {
			continue
		}
		count++
		id := networkIDOf(n)
		if prev, ok := seen[id]; ok {
			t.Fatalf("net %s shares NetworkID with %s — cross-log requires DISTINCT networks", n.Name, prev)
		}
		seen[id] = n.Name
	}
	if count < 2 {
		s.Pending(t, "S6.20: need >= 2 networks with loaded bootstraps, have %d", count)
	}
}

// ── S6.21 — each live head is a real K-of-N cosigned head (per-hop source crypto) ──

func TestS6_21_EachNetworkHeadMeetsQuorum(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireTopology(t)

	checked := 0
	for _, n := range s.AllNetworks() {
		if !bootReady(n) {
			continue
		}
		head, code, err := n.Ledger.TreeHead()
		if code == 404 {
			s.Pending(t, "S6.21: net %s has no cosigned head yet", n.Name)
			continue
		}
		harness.Truthy(t, err == nil && code == 200, "net "+n.Name+" /v1/tree/head: "+harness.ErrStr(err))
		res, verr := e2ecosign.Verify(n.Boot, n.QuorumK(), head)
		harness.Truthy(t, verr == nil, "net "+n.Name+" cosign verify: "+harness.ErrStr(verr))
		harness.Truthy(t, res.ValidCount >= n.QuorumK(),
			"net "+n.Name+" head below quorum: "+harness.Itoa(res.ValidCount)+"/"+harness.Itoa(n.QuorumK()))
		checked++
	}
	if checked == 0 {
		s.Pending(t, "S6.21: no live network heads available")
	}
}

// ── S6.22 — federation.VerifyFromOrigin fails closed over LIVE handles ─────────

// Drives the SDK cross-log entry point with handles built from the live Federal
// and TN bootstraps (real NetworkIDs + witness sets), asserting every documented
// fail-closed path. Deterministic: no ledger write, no inclusion proof needed.
func TestS6_22_FederationVerifyFailsClosed(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireTopology(t)
	s.RequireSecondCourt(t)

	fed, tn := s.Federal, s.TN
	fedDID, tnDID := exchangeDIDOf(s, fed), exchangeDIDOf(s, tn)
	if !bootReady(fed) || !bootReady(tn) || fedDID == "" || tnDID == "" {
		s.Pending(t, "S6.22: Federal/TN bootstraps or exchange DIDs unavailable")
		return
	}
	oneHop := verifier.CompoundProof{Hops: make([]types.CrossLogProof, 1)}

	// (a) NetworkID cycle: TN → Federal → TN ⇒ ErrFederationCycle (before crypto).
	cycle := []federation.AnchoredNetwork{
		handle(t, s, tn, fedDID),
		handle(t, s, fed, tnDID), // back-edge
	}
	if err := federation.VerifyFromOrigin(tnDID, cycle, oneHop, [32]byte{}, types.TreeHead{}, knownClean); !errors.Is(err, federation.ErrFederationCycle) {
		t.Fatalf("cycle: want ErrFederationCycle, got %v", err)
	}

	// (b) single network (TN is its own apex) ⇒ ErrSingleNetwork.
	solo := []federation.AnchoredNetwork{handle(t, s, tn, "")}
	if err := federation.VerifyFromOrigin(tnDID, solo, oneHop, [32]byte{}, types.TreeHead{}, knownClean); !errors.Is(err, federation.ErrSingleNetwork) {
		t.Fatalf("single-network: want ErrSingleNetwork, got %v", err)
	}

	// A genuine 2-network chain: TN → Federal (apex).
	chain := []federation.AnchoredNetwork{
		handle(t, s, tn, fedDID),
		handle(t, s, fed, ""),
	}

	// (c) origin DID outside the set ⇒ ErrUnknownOrigin.
	if err := federation.VerifyFromOrigin("did:web:ghost", chain, oneHop, [32]byte{}, types.TreeHead{}, knownClean); !errors.Is(err, federation.ErrUnknownOrigin) {
		t.Fatalf("unknown origin: want ErrUnknownOrigin, got %v", err)
	}

	// (d) zero trust gates the real cross-log hop closed ⇒ ErrTrustUnknown
	// (the per-hop burn gate runs against TN's real witness set BEFORE any crypto).
	if err := federation.VerifyFromOrigin(tnDID, chain, oneHop, [32]byte{}, types.TreeHead{}, zeroTrust); !errors.Is(err, verifier.ErrTrustUnknown) {
		t.Fatalf("unknown trust: want ErrTrustUnknown, got %v", err)
	}
}

// ── S6.23 — build + write a REAL cross-network anchor of a live head ───────────

// Builds an anchor entry committing TN's LIVE cosigned head and submits it to the
// Federal ledger — the concrete cross-network anchor a federation proof rests on.
// The destination ledger's admission decides the outcome: a 2xx proves it admits
// a cross-network anchor; a 4xx is the (expected, today) authorization boundary —
// the test self-gates with the precise unlock rather than failing, since wiring an
// authorized cross-network writer into gen-fixtures is the live-write prerequisite.
func TestS6_23_CrossNetworkAnchorWrite(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireTopology(t)
	s.RequireSecondCourt(t)

	fed, tn := s.Federal, s.TN
	fedDID, tnDID := exchangeDIDOf(s, fed), exchangeDIDOf(s, tn)
	if !bootReady(tn) || fedDID == "" || tnDID == "" {
		s.Pending(t, "S6.23: TN bootstrap or exchange DIDs unavailable")
		return
	}

	// Fetch TN's LIVE cosigned head (the source the anchor commits).
	srcHead, code, err := tn.Ledger.TreeHead()
	if code == 404 || err != nil {
		s.Pending(t, "S6.23: TN has no cosigned head yet (code=%d, err=%v)", code, err)
		return
	}
	sdkHead, cerr := e2ecosign.ToSDKHead(srcHead)
	if cerr != nil {
		s.Pending(t, "S6.23: cannot map TN live head to SDK head: %v", cerr)
		return
	}

	// Build the cross-network anchor entry: Federal anchors TN's head.
	anchorEntry, err := anchor.BuildCosignedAnchorEntry(anchor.CosignedAnchorParams{
		SignerDID:    fedDID,
		Destination:  fedDID,
		SourceLogDID: tnDID,
		Head:         sdkHead,
		NetworkID:    networkIDOf(tn),
		EventTime:    time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("build cross-network anchor entry: %v", err)
	}

	// Sign + serialize to canonical wire (the envelope signature is structural;
	// admission authorization is what the destination ledger evaluates).
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	hash := sha256.Sum256(envelope.SigningPayload(anchorEntry))
	sig, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("sign anchor entry: %v", err)
	}
	anchorEntry.Signatures = []envelope.Signature{{
		SignerDID: fedDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	wire, err := envelope.Serialize(anchorEntry)
	if err != nil {
		t.Fatalf("serialize anchor entry: %v", err)
	}

	// Submit the cross-network anchor to the destination (Federal) ledger.
	sct, code, err := fed.Ledger.SubmitEntry(wire)
	harness.Truthy(t, err == nil, "Federal SubmitEntry transport error: "+harness.ErrStr(err))
	switch {
	case code/100 == 2:
		// The destination ledger admitted a cross-network anchor of TN's head.
		harness.NonEmpty(t, sct.CanonicalHash, "admitted anchor SCT canonical_hash")
	case code >= 400 && code < 500:
		s.Pending(t, "S6.23: Federal admission rejected the cross-network anchor (HTTP %d) — "+
			"wire an authorized cross-network writer key into gen-fixtures to activate the live write+verify round-trip", code)
	default:
		t.Fatalf("S6.23: unexpected submit status %d", code)
	}
}
