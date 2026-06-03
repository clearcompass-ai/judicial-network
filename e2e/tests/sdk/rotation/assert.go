package rotation

import (
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/witness"

	"github.com/clearcompass-ai/judicial-network/e2e/tests/sdk/equivocation"
)

// sameSet asserts a reconstructed witness key set matches an expected era.
func sameSet(tb testing.TB, got *cosign.WitnessKeySet, want *equivocation.WitnessSet, label string) {
	tb.Helper()
	gk := got.Keys()
	if len(gk) != len(want.Keys) {
		tb.Fatalf("%s: reconstructed set size %d, want %d", label, len(gk), len(want.Keys))
	}
	for i := range want.Keys {
		if gk[i].ID != want.Keys[i].ID {
			tb.Fatalf("%s: reconstructed key %d does not match the expected era set", label, i)
		}
	}
}

// AssertVerifiedHistoryEraCorrect — UC-ROT-4 (year-1 vs year-15): a PROVABLE
// multi-era history reconstructs the era-correct witness set at any historical
// position, and a null as-of is rejected (ZT-IMM-01). This is the position-aware
// reconstruction that lets a year-1 head be judged under the year-1 set.
func AssertVerifiedHistoryEraCorrect(tb testing.TB, eras []*equivocation.WitnessSet, logDID string) {
	tb.Helper()
	hist, positions, err := BuildVerifiedHistory(eras, logDID, 8)
	if err != nil {
		tb.Fatalf("BuildVerifiedHistory: %v", err)
	}
	if hist.Len() != len(eras)-1 {
		tb.Fatalf("history Len = %d, want %d", hist.Len(), len(eras)-1)
	}
	// Year 1: a position BEFORE the first rotation resolves to the genesis set.
	setEarly, err := hist.At(types.LogPosition{LogDID: logDID, Sequence: 0})
	if err != nil {
		tb.Fatalf("At(year-1): %v", err)
	}
	sameSet(tb, setEarly, eras[0], "year-1")
	// Year 15: at/after the last rotation, the final era's set is authoritative.
	setLast, err := hist.At(positions[len(positions)-1])
	if err != nil {
		tb.Fatalf("At(year-15): %v", err)
	}
	sameSet(tb, setLast, eras[len(eras)-1], "year-15")
	// A mid-history position resolves to the era in effect there.
	mid := len(positions) / 2
	setMid, err := hist.At(positions[mid])
	if err != nil {
		tb.Fatalf("At(mid): %v", err)
	}
	sameSet(tb, setMid, eras[mid+1], "mid")
	// ZT-IMM-01: a null as-of is rejected (no wall-clock / "latest" default).
	if _, err := hist.At(types.LogPosition{}); err == nil {
		tb.Fatalf("At(null asOf) accepted — AsOf must be mandatory (ZT-IMM-01)")
	}
}

// AssertRotationChainAuthorized — UC-ROT (year-1 → year-15): a chain of
// witness-set rotations is verifiable — each rotation is authorized by its
// immediate predecessor's quorum, and VerifyRotationChain reconstructs the final
// (year-15) set from genesis. This is the "verify-before-swap" property at the
// crypto core: a set only takes effect if the prior set signed it.
func AssertRotationChainAuthorized(tb testing.TB, eras []*equivocation.WitnessSet) {
	tb.Helper()
	if len(eras) < 2 {
		tb.Fatalf("need >=2 eras, have %d", len(eras))
	}
	rotations, err := Chain(eras)
	if err != nil {
		tb.Fatalf("Chain: %v", err)
	}
	// Each step verifies under its immediate predecessor (year i authorizes year i+1).
	set := eras[0]
	for i, rot := range rotations {
		if _, verr := witness.VerifyRotation(rot, set.Set); verr != nil {
			tb.Fatalf("rotation %d→%d not authorized by its predecessor: %v", i, i+1, verr)
		}
		set = eras[i+1]
	}
	// The WHOLE chain (genesis → final) verifies and yields the final era's keys.
	finalKeys, err := witness.VerifyRotationChain(eras[0].Set, rotations)
	if err != nil {
		tb.Fatalf("VerifyRotationChain (year-1 → year-%d): %v", len(eras), err)
	}
	want := eras[len(eras)-1].Keys
	if len(finalKeys) != len(want) {
		tb.Fatalf("reconstructed final set size %d, want %d", len(finalKeys), len(want))
	}
	for i := range want {
		if finalKeys[i].ID != want[i].ID {
			tb.Fatalf("reconstructed final key %d != year-%d set", i, len(eras))
		}
	}
}

// AssertForgedRotationRejected — UC-ROT (negative): a rotation NOT signed by the
// CURRENT set's quorum is rejected — no silent set takeover, quorum enforced.
func AssertForgedRotationRejected(tb testing.TB, eras []*equivocation.WitnessSet) {
	tb.Helper()
	if len(eras) < 2 {
		tb.Fatalf("need >=2 eras, have %d", len(eras))
	}

	// (a) A rotation forged by a FOREIGN set (not the current set) is rejected.
	foreign, err := equivocation.NewWitnessSet(eras[0].N, eras[0].K, eras[0].NetworkID)
	if err != nil {
		tb.Fatalf("foreign set: %v", err)
	}
	forged, err := RotateFrom(foreign, eras[1], foreign.K) // signed by foreign, presented against era-0
	if err != nil {
		tb.Fatalf("RotateFrom(foreign): %v", err)
	}
	if _, verr := witness.VerifyRotation(forged, eras[0].Set); verr == nil {
		tb.Fatalf("a rotation forged by a foreign set was accepted against era-0 — SILENT TAKEOVER")
	}

	// (b) A sub-quorum rotation (k-1 of the current set) is rejected.
	if eras[0].K > 1 {
		sub, serr := RotateFrom(eras[0], eras[1], eras[0].K-1)
		if serr != nil {
			tb.Fatalf("RotateFrom(sub-quorum): %v", serr)
		}
		if _, verr := witness.VerifyRotation(sub, eras[0].Set); verr == nil {
			tb.Fatalf("a sub-quorum rotation was accepted — quorum NOT enforced")
		}
	}
}
