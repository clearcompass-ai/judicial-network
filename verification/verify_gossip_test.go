package verification

import (
	"context"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
)

const vgSrc = "did:web:source.log"

func TestGossipVerifier_CosignedTreeHead_HappyPath(t *testing.T) {
	w := newVGWitnesses(t, 3, 2)
	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{vgSrc: w.set}, w.nid)
	gv, err := NewGossipVerifier(GossipVerifierConfig{Envelope: stubEnvelope{}, WitnessSets: reg})
	if err != nil {
		t.Fatal(err)
	}
	f, err := findings.NewCosignedTreeHeadFinding(w.cosignedHead(t, 100, 0xAA), "ep")
	if err != nil {
		t.Fatal(err)
	}
	got, err := gv.Verify(context.Background(), signedEventForFinding(t, vgSrc, f))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Kind() != gossip.KindCosignedTreeHead {
		t.Fatalf("kind = %q", got.Kind())
	}
}

// Tier 1 gate: a forged/invalid envelope is rejected before any finding work.
func TestGossipVerifier_EnvelopeFails(t *testing.T) {
	w := newVGWitnesses(t, 1, 1)
	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{vgSrc: w.set}, w.nid)
	gv, _ := NewGossipVerifier(GossipVerifierConfig{
		Envelope:    stubEnvelope{err: errors.New("forged envelope")},
		WitnessSets: reg,
	})
	f, _ := findings.NewCosignedTreeHeadFinding(w.cosignedHead(t, 100, 0xAA), "ep")
	if _, err := gv.Verify(context.Background(), signedEventForFinding(t, vgSrc, f)); !errors.Is(err, ErrGossipVerify) {
		t.Fatalf("err = %v, want ErrGossipVerify", err)
	}
}

// Tier 2 gate: a head whose cosignatures don't match the LOCALLY-trusted set is
// rejected even though the envelope passed.
func TestGossipVerifier_WrongWitnessSetFailsFindingProof(t *testing.T) {
	w := newVGWitnesses(t, 3, 2)
	other := newVGWitnesses(t, 3, 2)
	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{vgSrc: other.set}, w.nid)
	gv, _ := NewGossipVerifier(GossipVerifierConfig{Envelope: stubEnvelope{}, WitnessSets: reg})
	f, _ := findings.NewCosignedTreeHeadFinding(w.cosignedHead(t, 100, 0xAA), "ep")
	if _, err := gv.Verify(context.Background(), signedEventForFinding(t, vgSrc, f)); !errors.Is(err, ErrGossipVerify) {
		t.Fatalf("err = %v, want ErrGossipVerify", err)
	}
}

// A self-attested Kind (originator rotation) verifies on envelope authenticity
// alone — no witness set required.
func TestGossipVerifier_OriginatorRotation_SelfAttested(t *testing.T) {
	w := newVGWitnesses(t, 1, 1)
	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{}, w.nid)
	gv, _ := NewGossipVerifier(GossipVerifierConfig{Envelope: stubEnvelope{}, WitnessSets: reg})
	f, err := findings.NewOriginatorRotationFinding([]byte{0x02, 0x01, 0x03}, [32]byte{0x09})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gv.Verify(context.Background(), signedEventForFinding(t, "did:peer", f)); err != nil {
		t.Fatalf("self-attested verify: %v", err)
	}
}

func TestGossipVerifier_UnknownKindFailsDecode(t *testing.T) {
	w := newVGWitnesses(t, 1, 1)
	reg := NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{}, w.nid)
	gv, _ := NewGossipVerifier(GossipVerifierConfig{Envelope: stubEnvelope{}, WitnessSets: reg})
	ev := gossip.SignedEvent{Kind: "AT-GOSSIP-NOPE-V1", Originator: "did:peer", Body: []byte(`{}`)}
	if _, err := gv.Verify(context.Background(), ev); !errors.Is(err, ErrGossipVerify) {
		t.Fatalf("err = %v, want ErrGossipVerify", err)
	}
}

func TestNewGossipVerifier_RequiresRegistry(t *testing.T) {
	if _, err := NewGossipVerifier(GossipVerifierConfig{Envelope: stubEnvelope{}}); !errors.Is(err, ErrGossipVerify) {
		t.Fatalf("err = %v, want ErrGossipVerify", err)
	}
}
