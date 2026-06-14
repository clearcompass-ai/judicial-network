package main

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/api/config"
)

// TestCrossCheckHomeWitnessSet locks PRE-11 Phase B's home-log demotion:
// a WitnessSetConfig restating the home log must match the constitution's
// genesis_witness_set exactly (as a DID set) or boot is refused. The on-log
// genesis set is authority; the config copy may only agree.
func TestCrossCheckHomeWitnessSet(t *testing.T) {
	genesis := []string{"did:key:a", "did:key:b", "did:key:c"}

	// Exact match, order-independent ⇒ ok.
	if err := crossCheckHomeWitnessSet(config.WitnessSetConfig{
		LogDID:      "did:home",
		WitnessDIDs: []string{"did:key:c", "did:key:a", "did:key:b"},
		QuorumK:     2,
	}, genesis); err != nil {
		t.Fatalf("matching home set must pass: %v", err)
	}

	// A DID absent from the constitution ⇒ refuse boot (the rogue-restate case).
	if err := crossCheckHomeWitnessSet(config.WitnessSetConfig{
		LogDID:      "did:home",
		WitnessDIDs: []string{"did:key:a", "did:key:b", "did:key:rogue"},
		QuorumK:     2,
	}, genesis); err == nil {
		t.Fatal("a witness DID absent from genesis_witness_set must refuse boot")
	}

	// Count drift ⇒ refuse boot.
	if err := crossCheckHomeWitnessSet(config.WitnessSetConfig{
		LogDID:      "did:home",
		WitnessDIDs: []string{"did:key:a", "did:key:b"},
		QuorumK:     1,
	}, genesis); err == nil {
		t.Fatal("witness-count drift must refuse boot")
	}
}
