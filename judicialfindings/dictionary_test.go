// FILE PATH: judicialfindings/dictionary_test.go
//
// Routes a REAL instance of every Kind in the SDK's closed gossip event
// dictionary (gossip/kind.go) through the JN router, proving each is both
// correctly classified AND dispatched to a verification path its concrete
// finding type actually supports. The prior router tests used stub events
// that implemented the class interfaces by construction, so they could not
// catch a real finding whose type does NOT implement its registered class's
// interface (the OriginatorRotation / EscrowOverride misclassification).
package judicialfindings

import (
	"context"
	"strings"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/witness"
)

const srcLog = "did:web:source.log"

// JN's Registry must classify EVERY Kind the SDK's closed dictionary ships —
// no SDK Kind unadopted, no JN entry pointing at a Kind the SDK dropped.
func TestRegistry_CoversEntireSDKDictionary(t *testing.T) {
	for _, k := range gossip.RegisteredKinds() {
		if _, ok := LookupClass(string(k)); !ok {
			t.Errorf("SDK Kind %q has no JN Registry class — dictionary not fully adopted", k)
		}
	}
	for k := range Registry {
		if !gossip.IsRegisteredKind(gossip.Kind(k)) {
			t.Errorf("JN Registry entry %q is not an SDK-registered Kind", k)
		}
	}
}

func witnessVC(wf witnessFixture) VerificationContext {
	return VerificationContext{
		SourceLogDID: srcLog,
		WitnessSets:  map[string]*cosign.WitnessKeySet{srcLog: wf.set},
	}
}

// ── ClassWitness ──────────────────────────────────────────────────────────

func TestRoute_CosignedTreeHead_Witness(t *testing.T) {
	wf := newWitnessFixture(t, 3, 2)
	f, err := findings.NewCosignedTreeHeadFinding(wf.cosignedHead(t, 100, [32]byte{0xAA}), "ep")
	if err != nil {
		t.Fatalf("NewCosignedTreeHeadFinding: %v", err)
	}
	if err := Verify(context.Background(), f, witnessVC(wf)); err != nil {
		t.Fatalf("STH route: %v", err)
	}
}

func TestRoute_Equivocation_Witness(t *testing.T) {
	wf := newWitnessFixture(t, 3, 2)
	proof := witness.EquivocationProof{
		TreeSize:   100,
		HeadA:      wf.cosignedHead(t, 100, [32]byte{0xAA}),
		HeadB:      wf.cosignedHead(t, 100, [32]byte{0xBB}),
		ValidSigsA: 3,
		ValidSigsB: 3,
	}
	f, err := findings.NewEquivocationFinding(proof, "ep")
	if err != nil {
		t.Fatalf("NewEquivocationFinding: %v", err)
	}
	if err := Verify(context.Background(), f, witnessVC(wf)); err != nil {
		t.Fatalf("equivocation route: %v", err)
	}
}

// EscrowOverrideFinding does NOT implement WitnessAttested; the router's
// bridge must still verify its K-of-N quorum via cosign.Verify — and reject a
// wrong witness set rather than silently passing it as envelope-only.
func TestRoute_EscrowOverride_BridgeVerifiesQuorum(t *testing.T) {
	wf := newWitnessFixture(t, 3, 2)
	payload := cosign.NewEscrowOverridePayload([32]byte{0x11}, [32]byte{0x22}, 1234)
	f, err := findings.NewEscrowOverrideFinding(payload, wf.cosignEscrow(t, payload))
	if err != nil {
		t.Fatalf("NewEscrowOverrideFinding: %v", err)
	}
	if err := Verify(context.Background(), f, witnessVC(wf)); err != nil {
		t.Fatalf("escrow route (happy): %v", err)
	}
	other := newWitnessFixture(t, 3, 2)
	if err := Verify(context.Background(), f, witnessVC(other)); err == nil {
		t.Fatal("escrow override under a foreign witness set must fail quorum")
	}
}

// WitnessRotationFinding implements WitnessAttested; a real instance must
// dispatch to the witness Verify path (not the does-not-implement default).
func TestRoute_WitnessRotation_ReachesVerify(t *testing.T) {
	wf := newWitnessFixture(t, 2, 1)
	rot := types.WitnessRotation{
		CurrentSetHash:    [32]byte{0x01},
		NewSet:            wf.set.Keys(),
		SchemeTagOld:      signatures.SchemeECDSA,
		CurrentSignatures: []types.WitnessSignature{{PubKeyID: [32]byte{0x02}, SchemeTag: signatures.SchemeECDSA, SigBytes: []byte{0xAA}}},
		SchemeTagNew:      signatures.SchemeECDSA,
		NewSignatures:     []types.WitnessSignature{{PubKeyID: [32]byte{0x03}, SchemeTag: signatures.SchemeECDSA, SigBytes: []byte{0xBB}}},
	}
	f, err := findings.NewWitnessRotationFinding(rot, "ep")
	if err != nil {
		t.Fatalf("NewWitnessRotationFinding: %v", err)
	}
	// Bogus signatures → Verify fails crypto, but the error must come from the
	// witness verify STAGE, proving correct dispatch + interface satisfaction.
	err = Verify(context.Background(), f, witnessVC(wf))
	if err == nil || !strings.Contains(err.Error(), "witness verify") {
		t.Fatalf("want witness-verify-stage error, got %v", err)
	}
}

// ── ClassSigner ───────────────────────────────────────────────────────────

func TestRoute_EntryCommitmentEquivocation_Signer(t *testing.T) {
	f, err := findings.NewEntryCommitmentEquivocationFinding(
		"did:web:equivocator", "schema-x", [32]byte{0x55},
		findings.EntryEquivocatedSide{CanonicalHash: [32]byte{0x01}, EntrySeq: 1, SigBytes: []byte{0xAA}},
		findings.EntryEquivocatedSide{CanonicalHash: [32]byte{0x02}, EntrySeq: 2, SigBytes: []byte{0xBB}},
	)
	if err != nil {
		t.Fatalf("NewEntryCommitmentEquivocationFinding: %v", err)
	}
	// No SignerVerifier supplied: the router must reach the SIGNER branch
	// (proving ClassSigner dispatch + SignerAttested satisfaction) and report
	// the missing dependency — not a does-not-implement classification error.
	err = Verify(context.Background(), f, VerificationContext{})
	if err == nil || !strings.Contains(err.Error(), "SignerVerifier") {
		t.Fatalf("want SignerVerifier-required error, got %v", err)
	}
}

// ── ClassMerkle ───────────────────────────────────────────────────────────

func TestRoute_CrossLogInclusion_Merkle(t *testing.T) {
	f, err := findings.NewCrossLogInclusionFinding(srcLog, 5, [32]byte{0x77}, 100, 1_700_000_000_000_000_000)
	if err != nil {
		t.Fatalf("NewCrossLogInclusionFinding: %v", err)
	}
	// No TileFetcher: the router must reach the MERKLE branch (proving
	// ClassMerkle dispatch + MerkleAttested satisfaction) and report the
	// missing dependency.
	err = Verify(context.Background(), f, VerificationContext{})
	if err == nil || !strings.Contains(err.Error(), "TileFetcher") {
		t.Fatalf("want TileFetcher-required error, got %v", err)
	}
}

// ── ClassSelfAttested ─────────────────────────────────────────────────────

// OriginatorRotationFinding is the I5 single-identity rotation. It implements
// only gossip.Event — its authority is the gossip envelope, so it routes as
// self-attested and verifies with no witness set / signer verifier.
func TestRoute_OriginatorRotation_SelfAttested(t *testing.T) {
	f, err := findings.NewOriginatorRotationFinding([]byte{0x02, 0x01, 0x03}, [32]byte{0x09})
	if err != nil {
		t.Fatalf("NewOriginatorRotationFinding: %v", err)
	}
	if err := Verify(context.Background(), f, VerificationContext{}); err != nil {
		t.Fatalf("originator rotation route: %v", err)
	}
}

func TestRoute_GhostLeaf_SelfAttested(t *testing.T) {
	f, err := findings.NewGhostLeafFinding(7, 3, [32]byte{0xAB}, "did:web:log", 1_700_000_000_000_000_000)
	if err != nil {
		t.Fatalf("NewGhostLeafFinding: %v", err)
	}
	if err := Verify(context.Background(), f, VerificationContext{}); err != nil {
		t.Fatalf("ghost leaf route: %v", err)
	}
}
