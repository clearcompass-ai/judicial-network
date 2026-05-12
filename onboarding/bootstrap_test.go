// FILE PATH: onboarding/bootstrap_test.go
//
// Tests for Phase 8 bootstrap wrappers. Validates the JN-side
// pre-flight checks + certificate formatting. The SDK's
// verifier.HardcodedGenesis / AnchorLogSync / TrustOnFirstUse
// are the cryptographic source of truth (covered in
// attesta/verifier/bootstrap_test.go); these tests cover:
//
//  1. HardcodedGenesis rejects empty court_did (ErrBootstrap).
//  2. AnchorLogSync rejects nil client (ErrBootstrap).
//  3. AnchorLogSync rejects empty court_did (ErrBootstrap).
//  4. TrustOnFirstUse rejects empty court_did.
//  5. BootstrapMode constants have stable string values
//     (CLI flags + dashboard panels query on these).
//  6. Summary() on a nil receiver returns the empty string
//     (defensive — runbooks pipe Summary output into shell
//     concatenation where nil is non-fatal).
//  7. Summary() on a populated certificate emits the expected
//     stable shape.
package onboarding

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHardcodedGenesis_RejectsEmptyCourtDID(t *testing.T) {
	_, err := HardcodedGenesis(HardcodedGenesisInput{})
	if !errors.Is(err, ErrBootstrap) {
		t.Fatalf("want ErrBootstrap, got %v", err)
	}
}

func TestAnchorLogSync_RejectsEmptyCourtDID(t *testing.T) {
	_, err := AnchorLogSync(context.Background(), AnchorLogSyncInput{})
	if !errors.Is(err, ErrBootstrap) {
		t.Fatalf("want ErrBootstrap, got %v", err)
	}
}

func TestAnchorLogSync_RejectsNilClient(t *testing.T) {
	_, err := AnchorLogSync(context.Background(), AnchorLogSyncInput{
		CourtDID: "did:web:courts.example",
	})
	if !errors.Is(err, ErrBootstrap) {
		t.Fatalf("want ErrBootstrap (nil client), got %v", err)
	}
}

func TestTrustOnFirstUse_RejectsEmptyCourtDID(t *testing.T) {
	_, err := TrustOnFirstUse(TrustOnFirstUseInput{})
	if !errors.Is(err, ErrBootstrap) {
		t.Fatalf("want ErrBootstrap, got %v", err)
	}
}

func TestBootstrapMode_StableValues(t *testing.T) {
	// CLI --method flag values + dashboard panels query on
	// these exact strings. Test fails if they ever drift
	// without coordinated downstream updates.
	want := map[BootstrapMode]string{
		ModeHardcodedGenesis: "hardcoded-genesis",
		ModeAnchorLogSync:    "anchor-log-sync",
		ModeTrustOnFirstUse:  "trust-on-first-use",
	}
	for m, s := range want {
		if string(m) != s {
			t.Errorf("BootstrapMode %v drifted: got %q want %q", m, string(m), s)
		}
	}
}

func TestSummary_NilCertificate(t *testing.T) {
	var c *BootstrapCertificate
	if got := c.Summary(); got != "" {
		t.Fatalf("nil Summary should be empty, got %q", got)
	}
}

func TestSummary_PopulatedCertificate(t *testing.T) {
	c := &BootstrapCertificate{
		Method:        ModeHardcodedGenesis,
		CourtDID:      "did:web:courts.davidson.example",
		QuorumK:       3,
		WitnessCount:  5,
		TreeSize:      9876,
		EstablishedAt: time.Date(2026, 5, 12, 8, 0, 0, 0, time.UTC),
	}
	got := c.Summary()
	mustContain := []string{
		"method=hardcoded-genesis",
		"court=did:web:courts.davidson.example",
		"K=3",
		"witnesses=5",
		"tree_size=9876",
		"established_at=2026-05-12T08:00:00Z",
	}
	for _, frag := range mustContain {
		if !strings.Contains(got, frag) {
			t.Errorf("Summary missing %q: %s", frag, got)
		}
	}
}
