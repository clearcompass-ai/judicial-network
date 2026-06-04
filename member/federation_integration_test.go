package member

// Integration proof that JN's CONCRETE network handle (TNCourtSystem) plugs into
// the SDK's reusable cross-log building block — federation.VerifyFromOrigin —
// with trust sourced from JN's own heads-journal chokepoint
// (verification/trust.StatusFor). JN re-implements NONE of the walk/verify glue;
// it supplies only its networks and a trust closure.
//
// The exhaustive GREEN/real-crypto cross-log validation lives in the SDK
// (baseproof/federation/cross_network_scale_test.go) and is re-exercised by the
// e2e gate, so here we assert the JN-specific surface: the concrete handle is
// consumable, and the topology/trust guards fire fail-closed through JN's stack.
// (Trust gates BEFORE any crypto, so nil witness sets suffice for these guards.)

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/federation"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"

	jntrust "github.com/clearcompass-ai/judicial-network/verification/trust"
)

// Compile-time: a TNCourtSystem is a usable federation.AnchoredNetwork handle.
var _ = federation.AnchoredNetwork{DID: "did:web:state:tn", Network: (*TNCourtSystem)(nil)}

func fedNetID(b byte) cosign.NetworkID { var id cosign.NetworkID; id[0] = b; return id }

const (
	stateDID = "did:web:state:tn"
	fedDID   = "did:web:fed"
)

// stateFederal models the canonical 2-network cross-log stack: the State network
// (one log) anchors into the Federal network (one log, apex). Witness sets are
// nil — these guards fire before any cryptography.
func stateFederal() []federation.AnchoredNetwork {
	return []federation.AnchoredNetwork{
		{DID: stateDID, Network: New(fedNetID(0x51), fedDID, nil, nil)}, // State → Federal
		{DID: fedDID, Network: New(fedNetID(0xFE), "", nil, nil)},       // Federal apex
	}
}

// one-hop proof shell — enough structure to reach the per-hop trust gate.
func oneHopShell() verifier.CompoundProof {
	return verifier.CompoundProof{Hops: make([]types.CrossLogProof, 1)}
}

func anyKnown(string) verifier.TrustStatus { return verifier.TrustStatus{Known: true} }

// The JN heads-journal chokepoint with NO journal yields Known=false, which
// gates the cross-log hop closed with ErrTrustUnknown — proving StatusFor binds
// straight through VerifyFromOrigin (fail-closed by construction).
func TestTNCourtSystem_VerifyFromOrigin_TrustChokepointFailsClosed(t *testing.T) {
	trustForDID := func(logDID string) verifier.TrustStatus {
		return jntrust.StatusFor(context.Background(), nil, logDID) // nil journal ⇒ unknown
	}
	err := federation.VerifyFromOrigin(stateDID, stateFederal(), oneHopShell(), [32]byte{}, types.TreeHead{}, trustForDID)
	if !errors.Is(err, verifier.ErrTrustUnknown) {
		t.Fatalf("want ErrTrustUnknown via StatusFor(nil journal), got %v", err)
	}
}

// An origin DID outside the network set fails closed.
func TestTNCourtSystem_VerifyFromOrigin_UnknownOrigin(t *testing.T) {
	err := federation.VerifyFromOrigin("did:web:ghost", stateFederal(), oneHopShell(), [32]byte{}, types.TreeHead{}, anyKnown)
	if !errors.Is(err, federation.ErrUnknownOrigin) {
		t.Fatalf("want ErrUnknownOrigin, got %v", err)
	}
}

// Starting at the Federal apex is a single network — no cross-log boundary to
// cross — and fails closed.
func TestTNCourtSystem_VerifyFromOrigin_SingleNetwork(t *testing.T) {
	err := federation.VerifyFromOrigin(fedDID, stateFederal(), oneHopShell(), [32]byte{}, types.TreeHead{}, anyKnown)
	if !errors.Is(err, federation.ErrSingleNetwork) {
		t.Fatalf("want ErrSingleNetwork, got %v", err)
	}
}

// A misconfigured mutual anchor (State ↔ Federal) is a NetworkID cycle and fails
// closed at the walk, before any crypto.
func TestTNCourtSystem_VerifyFromOrigin_CycleFailsClosed(t *testing.T) {
	nets := []federation.AnchoredNetwork{
		{DID: stateDID, Network: New(fedNetID(0x51), fedDID, nil, nil)},
		{DID: fedDID, Network: New(fedNetID(0xFE), stateDID, nil, nil)}, // back-edge ⇒ cycle
	}
	err := federation.VerifyFromOrigin(stateDID, nets, oneHopShell(), [32]byte{}, types.TreeHead{}, anyKnown)
	if !errors.Is(err, federation.ErrFederationCycle) {
		t.Fatalf("want ErrFederationCycle, got %v", err)
	}
}
