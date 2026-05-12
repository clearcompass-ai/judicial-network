// FILE PATH: topology/originator_rotation.go
//
// DESCRIPTION:
//
//	Phase 6 — Originator rotation. When a court rotates its
//	ledger operator (e.g. AWS → Azure migration, or a recovery
//	from a slashed equivocator), the existing witness quorum
//	signs a *types.WitnessRotation event. The SDK's
//	witness.VerifyRotation enforces the K-of-N invariant; this
//	file wraps:
//
//	  - BuildRotationEvent: marshal a rotation for gossip emit.
//	  - VerifyRotationChain: walk an ordered slice of rotations
//	    starting from a genesis WitnessKeySet, returning the
//	    derived current key set.
//
//	Trust Alignment 3 (Cryptographic Topologies): "Changing a
//	Witness quorum requires an explicit KindOriginatorRotation
//	event, signed by the existing quorum." This file is JN's
//	thin wrapper around the SDK primitives; it never invents
//	cryptographic semantics.
//
// KEY DEPENDENCIES:
//   - attesta/witness: VerifyRotation, VerifyRotationChain
//   - attesta/types: WitnessRotation, WitnessPublicKey
//   - attesta/gossip/findings: NewOriginatorRotationFinding (for
//     gossip-side transport of the new key after a successful
//     rotation)
package topology

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/witness"
)

// ErrRotation indicates a structural fault in a rotation request
// or chain. Cryptographic failures bubble up the underlying SDK
// witness sentinel errors via errors.Is.
var ErrRotation = errors.New("topology/originator_rotation: invalid rotation")

// RotationCeremony describes one rotation: the new witness keys
// the existing quorum has signed for, plus the cosignatures
// proving it. The two-tag fields distinguish a dual-signed
// rotation (where both old AND new sets sign the bridge), which
// witness.VerifyRotation accepts as additional evidence.
type RotationCeremony struct {
	NewKeys       []types.WitnessPublicKey
	OldSchemeTag  byte
	OldSignatures []types.WitnessSignature
	NewSchemeTag  byte
	NewSignatures []types.WitnessSignature
}

// BuildRotation packages a RotationCeremony into the SDK shape
// the network admits. The current set's hash is computed via
// witness.ComputeSetHash so verifiers don't have to.
func BuildRotation(currentSet *cosign.WitnessKeySet, ceremony RotationCeremony) (types.WitnessRotation, error) {
	if currentSet == nil {
		return types.WitnessRotation{}, fmt.Errorf("%w: nil currentSet", ErrRotation)
	}
	if len(ceremony.NewKeys) == 0 {
		return types.WitnessRotation{}, fmt.Errorf("%w: empty NewKeys", ErrRotation)
	}
	if len(ceremony.OldSignatures) == 0 {
		return types.WitnessRotation{}, fmt.Errorf("%w: empty OldSignatures", ErrRotation)
	}
	currentHash := witness.ComputeSetHash(currentSet.Keys())
	return types.WitnessRotation{
		CurrentSetHash:    currentHash,
		NewSet:            append([]types.WitnessPublicKey(nil), ceremony.NewKeys...),
		SchemeTagOld:      ceremony.OldSchemeTag,
		CurrentSignatures: append([]types.WitnessSignature(nil), ceremony.OldSignatures...),
		SchemeTagNew:      ceremony.NewSchemeTag,
		NewSignatures:     append([]types.WitnessSignature(nil), ceremony.NewSignatures...),
	}, nil
}

// VerifyAndApply runs the SDK's witness.VerifyRotation against
// the supplied currentSet and returns the new set's key slice on
// success. Callers feed the returned keys into
// cosign.NewWitnessKeySet to construct the next-generation
// *WitnessKeySet, preserving SDK Principle 10 encapsulation
// (K + NetworkID are caller-supplied at the new-set
// construction site).
func VerifyAndApply(rotation types.WitnessRotation, currentSet *cosign.WitnessKeySet) ([]types.WitnessPublicKey, error) {
	if currentSet == nil {
		return nil, fmt.Errorf("%w: nil currentSet", ErrRotation)
	}
	newKeys, err := witness.VerifyRotation(rotation, currentSet)
	if err != nil {
		return nil, fmt.Errorf("topology/originator_rotation: verify: %w", err)
	}
	return newKeys, nil
}

// VerifyChain replays an ordered sequence of rotations starting
// from genesisSet. Returns the final key set on success or the
// first cryptographic failure encountered. This is the
// "stateless catch-up" path of SDK Principle 15 — an Auditor
// joining the network rebuilds the current witness topology
// without taxing the Ledger.
func VerifyChain(genesisSet *cosign.WitnessKeySet, rotations []types.WitnessRotation) ([]types.WitnessPublicKey, error) {
	if genesisSet == nil {
		return nil, fmt.Errorf("%w: nil genesisSet", ErrRotation)
	}
	keys, err := witness.VerifyRotationChain(genesisSet, rotations)
	if err != nil {
		return nil, fmt.Errorf("topology/originator_rotation: verify chain: %w", err)
	}
	return keys, nil
}

// PublishFinding constructs the gossip-side OriginatorRotation
// event that broadcasts the new key. Callers sign and emit via
// gossipfeed.Publisher.EmitEvidence (the rotation channel is
// evidentiary, not lossy — back-pressure surfaces explicitly).
func PublishFinding(newPublicKey []byte, checkpointEventID [32]byte) (*findings.OriginatorRotationFinding, error) {
	return findings.NewOriginatorRotationFinding(newPublicKey, checkpointEventID)
}
