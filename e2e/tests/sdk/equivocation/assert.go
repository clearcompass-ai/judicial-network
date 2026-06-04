package equivocation

import (
	"errors"
	"testing"

	"github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
	"github.com/baseproof/baseproof/witness"
)

// ledgerEndpoint is the source-endpoint hint stamped into findings built by the
// fixture (forensic only; not part of the equivocation math).
const ledgerEndpoint = "https://ledger.equivocation-fixture.test"

// These exported assertions are the SINGLE source of truth for the equivocation
// use cases, called from BOTH this package's local test (SDK tier, no infra) and
// the e2e suite (capture, build tag e2e). They take testing.TB so either tier
// can drive them.

// AssertEquivocationDetected — UC-EQ-1 (positive): a real fork is detected and
// provable, and wraps into a structurally-valid EquivocationFinding.
func AssertEquivocationDetected(tb testing.TB, ws *WitnessSet) {
	tb.Helper()
	const size = 4242
	headA, headB, err := ws.Fork(size)
	if err != nil {
		tb.Fatalf("Fork: %v", err)
	}
	proof, err := witness.DetectEquivocation(headA, headB, ws.Set)
	if err != nil {
		tb.Fatalf("DetectEquivocation(fork): unexpected error %v", err)
	}
	if proof == nil || !proof.IsProven() {
		tb.Fatalf("fork NOT detected as a proven equivocation (proof=%v)", proof)
	}
	if proof.TreeSize != size {
		tb.Errorf("proof.TreeSize=%d, want %d", proof.TreeSize, size)
	}
	f, err := findings.NewEquivocationFinding(*proof, ledgerEndpoint)
	if err != nil {
		tb.Fatalf("NewEquivocationFinding(real fork): %v", err)
	}
	if err := f.Validate(); err != nil {
		tb.Fatalf("EquivocationFinding.Validate(): %v", err)
	}
}

// AssertNoFalseSlash — UC-EQ-1 (negative): the detector NEVER fabricates an
// equivocation from heads that are not a fork validly cosigned BY THIS SET. This
// is the "slasher re-verifies → no false slash" property at the crypto core.
func AssertNoFalseSlash(tb testing.TB, ws *WitnessSet) {
	tb.Helper()
	const size = 7777

	// (a) Honest re-publish (same root) → no equivocation.
	hA, hB, err := ws.HonestPair(size)
	if err != nil {
		tb.Fatalf("HonestPair: %v", err)
	}
	if proof, derr := witness.DetectEquivocation(hA, hB, ws.Set); derr != nil || proof != nil {
		tb.Fatalf("honest re-publish flagged as equivocation (proof=%v err=%v) — FALSE SLASH", proof, derr)
	}

	honest, err := ws.CosignHead(size, fill(0xA1), fill(0xA2), ws.N)
	if err != nil {
		tb.Fatalf("CosignHead(honest): %v", err)
	}

	// (b) A divergent head cosigned by a FOREIGN set (wrong keys, same network)
	//     is NOT proof against THIS set: cosign.Verify fails quorum
	//     (ErrQuorumNotReached) → DetectEquivocation errors → no proof.
	foreign, err := NewWitnessSet(ws.N, ws.K, ws.NetworkID)
	if err != nil {
		tb.Fatalf("foreign set: %v", err)
	}
	forged, err := foreign.CosignHead(size, fill(0xB1), fill(0xB2), foreign.N)
	if err != nil {
		tb.Fatalf("foreign CosignHead: %v", err)
	}
	if proof, derr := witness.DetectEquivocation(honest, forged, ws.Set); derr == nil && proof != nil && proof.IsProven() {
		tb.Fatalf("foreign-cosigned head produced an equivocation proof against THIS set — FALSE SLASH")
	}

	// (c) A sub-quorum divergent head (K-1 sigs) is not a validly cosigned head →
	//     no proof.
	if ws.K > 1 {
		subQuorum, serr := ws.CosignHead(size, fill(0xB1), fill(0xB2), ws.K-1)
		if serr != nil {
			tb.Fatalf("sub-quorum CosignHead: %v", serr)
		}
		if proof, derr := witness.DetectEquivocation(honest, subQuorum, ws.Set); derr == nil && proof != nil && proof.IsProven() {
			tb.Fatalf("sub-quorum head produced an equivocation proof — FALSE SLASH")
		}
	}

	// A non-equivocation cannot be wrapped as a finding either.
	if _, ferr := findings.NewEquivocationFinding(witness.EquivocationProof{HeadA: hA, HeadB: hB}, ledgerEndpoint); ferr == nil {
		tb.Fatalf("NewEquivocationFinding accepted a same-root (non-equivocation) proof — structural guard missing")
	}
}

// AssertPositionAwareEraCorrect — UC-EQ-2 (ZT-SCN-02): an equivocation is
// confirmable ONLY against the witness set that actually cosigned it (its era),
// never a different era's set. A year-1 fork checked against the year-15 set is
// (correctly) NOT confirmable — which is exactly why position-aware verification
// resolves the era-correct set instead of the live snapshot.
func AssertPositionAwareEraCorrect(tb testing.TB) {
	tb.Helper()
	const size = 100100
	netID := NetworkIDFromLabel("equivocation-eras")

	era1, err := NewWitnessSet(3, 2, netID)
	if err != nil {
		tb.Fatalf("era1 set: %v", err)
	}
	// era15: same network, DIFFERENT keys — the set has rotated over the years.
	era15, err := NewWitnessSet(3, 2, netID)
	if err != nil {
		tb.Fatalf("era15 set: %v", err)
	}

	headA, headB, err := era1.Fork(size) // a year-1 equivocation, cosigned by era1
	if err != nil {
		tb.Fatalf("Fork: %v", err)
	}

	// Era-correct: confirms against the set that actually cosigned it.
	proof, err := witness.DetectEquivocation(headA, headB, era1.Set)
	if err != nil || proof == nil || !proof.IsProven() {
		tb.Fatalf("era-correct verification failed (err=%v proof=%v)", err, proof)
	}

	// Position-BLIND: the SAME heads checked against the year-15 set do NOT
	// confirm (different keys) — the failure a position-blind verifier hits.
	if p, derr := witness.DetectEquivocation(headA, headB, era15.Set); derr == nil && p != nil && p.IsProven() {
		tb.Fatalf("year-1 fork confirmed against the year-15 set — verification is not era-bound")
	}

	// The finding declares its anchors as AnchorByPosition at the shared size —
	// how a position-aware verifier knows to resolve the era-correct set by SIZE
	// (not by trusting a possibly-adversarial head to self-identify its era).
	f, err := findings.NewEquivocationFinding(*proof, ledgerEndpoint)
	if err != nil {
		tb.Fatalf("NewEquivocationFinding: %v", err)
	}
	anchors := f.WitnessSetAnchors()
	if len(anchors) == 0 {
		tb.Fatalf("equivocation finding declares no witness-set anchors (position-blind)")
	}
	for i, a := range anchors {
		if a.Mode != findings.AnchorByPosition {
			tb.Errorf("anchor[%d].Mode = %v, want AnchorByPosition (equivocation pins the era by SIZE)", i, a.Mode)
		}
	}
}

// AssertBurnFailsClosed — UC-EQ-3 / UC-XL-2: once a source log has equivocated it
// is BURNED, and every cross-log proof that depends on it must fail CLOSED.
// verifier.TrustStatus is the gate; anchor.VerifyCrossLog enforces it FIRST,
// before the proof is even examined (anchor/anchor.go).
func AssertBurnFailsClosed(tb testing.TB, ws *WitnessSet) {
	tb.Helper()

	// The zero value (trust never consulted) fails closed.
	if err := (verifier.TrustStatus{}).Gate(); !errors.Is(err, verifier.ErrTrustUnknown) {
		tb.Fatalf("zero TrustStatus.Gate() = %v, want ErrTrustUnknown (fail-closed)", err)
	}
	// A burned (equivocated) source fails closed.
	burned := verifier.TrustStatus{Known: true, Burned: true}
	if err := burned.Gate(); !errors.Is(err, verifier.ErrEquivocatedLog) {
		tb.Fatalf("burned TrustStatus.Gate() = %v, want ErrEquivocatedLog", err)
	}
	// A known-good source passes the gate.
	if err := (verifier.TrustStatus{Known: true}).Gate(); err != nil {
		tb.Fatalf("known-good TrustStatus.Gate() = %v, want nil", err)
	}

	// anchor.VerifyCrossLog enforces the SAME gate FIRST: a burned source fails
	// closed before the proof is parsed (so even a zero proof returns the burn
	// error, not a proof-parse error). This is UC-XL-2: a pin into a burned log
	// is refused.
	if err := anchor.VerifyCrossLog(types.CrossLogProof{}, ws.Set, burned); !errors.Is(err, verifier.ErrEquivocatedLog) {
		tb.Fatalf("anchor.VerifyCrossLog(burned) = %v, want ErrEquivocatedLog (gate-first, fail-closed)", err)
	}
	if err := anchor.VerifyCrossLog(types.CrossLogProof{}, ws.Set, verifier.TrustStatus{}); !errors.Is(err, verifier.ErrTrustUnknown) {
		tb.Fatalf("anchor.VerifyCrossLog(unknown) = %v, want ErrTrustUnknown (gate-first, fail-closed)", err)
	}
}
