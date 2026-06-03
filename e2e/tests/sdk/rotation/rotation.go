// Package rotation is the SDK-tier witness-set / key-rotation fixture: a chain of
// witness sets (era 0 → era N, i.e. "year 1 → year 15") where each rotation is
// authorized by its predecessor's k-of-n signatures over the universal cosign
// rotation payload. It exercises the real attesta rotation primitives
// (witness.VerifyRotation / VerifyRotationChain / ComputeSetHash) with no live
// infrastructure: `go test ./rotation/` runs the whole chain on a desktop.
//
// SEGMENTATION: like ./equivocation, this is the SDK tier. The e2e suite captures
// the same assertions (tests/phase6_rotation_capture_test.go) so a Stack-B
// `make test` exercises them. The DEPLOYED rotation (ledger→auditor→JN
// verify-before-swap) is S6.9, which needs a running stack + a rotation driver.
package rotation

import (
	"fmt"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/witness"

	"github.com/clearcompass-ai/judicial-network/e2e/tests/sdk/equivocation"
)

// Eras builds a chain of n witness sets on ONE network (shared NetworkID + quorum
// so VerifyRotationChain can reconstruct each step) — the year-1..year-N timeline
// of a single log's witness fleet, each era an independently-keyed set.
func Eras(n, setN, setK int, label string) ([]*equivocation.WitnessSet, error) {
	if n < 2 {
		return nil, fmt.Errorf("rotation: need >=2 eras, got %d", n)
	}
	netID := equivocation.NetworkIDFromLabel(label)
	eras := make([]*equivocation.WitnessSet, n)
	for i := range eras {
		ws, err := equivocation.NewWitnessSet(setN, setK, netID)
		if err != nil {
			return nil, fmt.Errorf("rotation: era %d: %w", i, err)
		}
		eras[i] = ws
	}
	return eras, nil
}

// RotateFrom builds a rotation old → next, signed by sigCount of OLD's private
// keys over NewRotationPayloadSHA256(ComputeSetHash(next.Keys)) — the universal
// cosign rotation payload that witness.VerifyRotation(rotation, oldSet) checks.
func RotateFrom(old, next *equivocation.WitnessSet, sigCount int) (types.WitnessRotation, error) {
	payload := cosign.NewRotationPayloadSHA256(witness.ComputeSetHash(next.Keys))
	// Old-set authorization: the CURRENT set signs over the new set's hash.
	curSigs, err := signRotation(payload, old, sigCount)
	if err != nil {
		return types.WitnessRotation{}, fmt.Errorf("rotation: current-set sign: %w", err)
	}
	// New-set acknowledgement: the NEW authority signs the same payload, attesting
	// it accepts the role. Required by the on-log encoder; for a same-scheme
	// rotation VerifyRotation does not re-check it (the dual-sign path is skipped).
	newSigs, err := signRotation(payload, next, sigCount)
	if err != nil {
		return types.WitnessRotation{}, fmt.Errorf("rotation: new-set sign: %w", err)
	}
	return types.WitnessRotation{
		CurrentSetHash:    witness.ComputeSetHash(old.Keys),
		NewSet:            next.Keys,
		SchemeTagOld:      signatures.SchemeECDSA,
		CurrentSignatures: curSigs,
		SchemeTagNew:      signatures.SchemeECDSA,
		NewSignatures:     newSigs,
	}, nil
}

// signRotation signs the rotation payload with the first sigCount keys of ws.
func signRotation(payload cosign.RotationPayload, ws *equivocation.WitnessSet, sigCount int) ([]types.WitnessSignature, error) {
	sigs := make([]types.WitnessSignature, 0, sigCount)
	for i := 0; i < sigCount && i < ws.N; i++ {
		sb, err := cosign.SignECDSA(payload, ws.NetworkID, cosign.HashAlgoSHA256, ws.Privs[i])
		if err != nil {
			return nil, fmt.Errorf("SignECDSA witness %d: %w", i, err)
		}
		sigs = append(sigs, types.WitnessSignature{PubKeyID: ws.Keys[i].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sb})
	}
	return sigs, nil
}

// Chain builds the rotations linking each era to the next (eras[i] → eras[i+1]),
// each signed by eras[i]'s quorum.
func Chain(eras []*equivocation.WitnessSet) ([]types.WitnessRotation, error) {
	rotations := make([]types.WitnessRotation, 0, len(eras)-1)
	for i := 1; i < len(eras); i++ {
		rot, err := RotateFrom(eras[i-1], eras[i], eras[i-1].K)
		if err != nil {
			return nil, err
		}
		rotations = append(rotations, rot)
	}
	return rotations, nil
}
