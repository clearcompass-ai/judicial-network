package crosslog

import (
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/did"

	"github.com/clearcompass-ai/judicial-network/api/config"
)

// witnessDIDs returns n fresh did:key secp256k1 DIDs (the form
// witness.KeysFromDIDs resolves).
func witnessDIDs(t *testing.T, n int) []string {
	t.Helper()
	out := make([]string, n)
	for i := 0; i < n; i++ {
		kp, err := did.GenerateDIDKeySecp256k1()
		if err != nil {
			t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
		}
		out[i] = kp.DID
	}
	return out
}

func TestBuildWitnessSets_HappyPath(t *testing.T) {
	nid := testNetworkID()
	setA := config.WitnessSetConfig{LogDID: "did:web:log.a", WitnessDIDs: witnessDIDs(t, 3), QuorumK: 2}
	setB := config.WitnessSetConfig{LogDID: "did:web:log.b", WitnessDIDs: witnessDIDs(t, 4), QuorumK: 3}

	out, err := BuildWitnessSets([]config.WitnessSetConfig{setA, setB}, nid)
	if err != nil {
		t.Fatalf("BuildWitnessSets: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
	ks := out["did:web:log.a"]
	if ks == nil {
		t.Fatal("missing keyset for did:web:log.a")
	}
	if ks.Size() != 3 {
		t.Errorf("log.a Size = %d, want 3", ks.Size())
	}
	if ks.Quorum() != 2 {
		t.Errorf("log.a Quorum = %d, want 2", ks.Quorum())
	}
	if ks.NetworkID() != nid {
		t.Errorf("log.a NetworkID mismatch")
	}
	if out["did:web:log.b"].Quorum() != 3 {
		t.Errorf("log.b Quorum = %d, want 3", out["did:web:log.b"].Quorum())
	}
}

func TestBuildWitnessSets_EmptyYieldsNonNilMap(t *testing.T) {
	out, err := BuildWitnessSets(nil, testNetworkID())
	if err != nil {
		t.Fatalf("BuildWitnessSets(nil): %v", err)
	}
	if out == nil {
		t.Fatal("map must be non-nil")
	}
	if len(out) != 0 {
		t.Fatalf("len = %d, want 0", len(out))
	}
}

func TestBuildWitnessSets_RejectsEmptyLogDID(t *testing.T) {
	_, err := BuildWitnessSets([]config.WitnessSetConfig{
		{LogDID: "", WitnessDIDs: witnessDIDs(t, 2), QuorumK: 1},
	}, testNetworkID())
	if err == nil {
		t.Fatal("empty LogDID must error")
	}
}

func TestBuildWitnessSets_RejectsDuplicateLogDID(t *testing.T) {
	dup := config.WitnessSetConfig{LogDID: "did:web:dup", WitnessDIDs: witnessDIDs(t, 2), QuorumK: 1}
	_, err := BuildWitnessSets([]config.WitnessSetConfig{dup, dup}, testNetworkID())
	if err == nil {
		t.Fatal("duplicate LogDID must error")
	}
}

func TestBuildWitnessSets_RejectsBadWitnessDID(t *testing.T) {
	_, err := BuildWitnessSets([]config.WitnessSetConfig{
		{LogDID: "did:web:log", WitnessDIDs: []string{"did:web:not-a-key"}, QuorumK: 1},
	}, testNetworkID())
	if err == nil {
		t.Fatal("non-did:key witness must error")
	}
}

func TestBuildWitnessSets_RejectsQuorumAboveN(t *testing.T) {
	_, err := BuildWitnessSets([]config.WitnessSetConfig{
		{LogDID: "did:web:log", WitnessDIDs: witnessDIDs(t, 2), QuorumK: 3},
	}, testNetworkID())
	if err == nil {
		t.Fatal("quorum > N must error")
	}
}

func TestBuildWitnessSets_RejectsZeroNetworkID(t *testing.T) {
	_, err := BuildWitnessSets([]config.WitnessSetConfig{
		{LogDID: "did:web:log", WitnessDIDs: witnessDIDs(t, 2), QuorumK: 1},
	}, cosign.NetworkID{})
	if err == nil {
		t.Fatal("zero NetworkID must error")
	}
}
