package rotation

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/witness"

	"github.com/clearcompass-ai/judicial-network/e2e/tests/sdk/equivocation"
)

// signedRotationEntry builds a structurally-valid SIGNED on-log rotation entry
// (envelope.Serialize requires >=1 signature). The entry-author signature is not
// re-verified by the history walk — verifyRotationStep checks the rotation's own
// cosignatures + the covering head — so a fresh ad-hoc signer key suffices.
func signedRotationEntry(logDID string, payload []byte) ([]byte, error) {
	header := envelope.ControlHeader{SignerDID: logDID, Destination: logDID}
	unsigned, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		return nil, err
	}
	priv, err := signatures.GenerateKey()
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(envelope.SigningPayload(unsigned))
	sigBytes, err := signatures.SignEntry(hash, priv)
	if err != nil {
		return nil, err
	}
	signed, err := envelope.NewEntry(header, payload, []envelope.Signature{
		{SignerDID: logDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sigBytes},
	})
	if err != nil {
		return nil, err
	}
	return envelope.Serialize(signed)
}

// nonZero returns a non-zero 32-byte value (cosign rejects an all-zero SMTRoot).
func nonZero(b byte) [32]byte {
	var r [32]byte
	for i := range r {
		r[i] = b
	}
	return r
}

// BuildVerifiedHistory assembles a PROVABLE multi-era witness-set history over a
// real in-memory RFC-6962 tree (smt.StubMerkleTree). For each era transition it:
//
//   - encodes a REAL on-log rotation entry (envelope.Serialize of the cosign
//     rotation payload), appends its on-log leaf, and grows the tree past it;
//   - produces a REAL inclusion proof binding that leaf to a witness-cosigned
//     covering head (cosigned by the PRIOR set — the set authoritative at the
//     rotation's position);
//   - assembles a witness.VerifiedRotationRecord.
//
// witness.NewVerifiedWitnessSetHistory then re-PROVES the whole chain (every
// rotation's inclusion + the covering head's K-of-N), so hist.At(asOf) is a
// position-aware, fail-closed reconstruction — exactly the year-1/year-15
// "which set was authoritative back then" query. Returns the history and the
// EffectivePos of each rotation.
func BuildVerifiedHistory(eras []*equivocation.WitnessSet, logDID string, fillEach int) (*witness.VerifiedWitnessSetHistory, []types.LogPosition, error) {
	if len(eras) < 2 {
		return nil, nil, fmt.Errorf("rotation: need >=2 eras, have %d", len(eras))
	}
	tree := smt.NewStubMerkleTree()
	ctx := context.Background()

	appendFiller := func(n int, tag string) error {
		for j := 0; j < n; j++ {
			if _, err := tree.AppendLeaf([]byte(fmt.Sprintf("filler-%s-%d", tag, j))); err != nil {
				return err
			}
		}
		return nil
	}

	var (
		records   []witness.VerifiedRotationRecord
		positions []types.LogPosition
	)
	for i := 1; i < len(eras); i++ {
		if err := appendFiller(fillEach, fmt.Sprintf("pre%d", i)); err != nil {
			return nil, nil, err
		}

		// 1. The rotation eras[i-1] → eras[i], encoded as a real on-log entry.
		rot, err := RotateFrom(eras[i-1], eras[i], eras[i-1].K)
		if err != nil {
			return nil, nil, err
		}
		payload, err := witness.EncodeWitnessRotationPayload(rot)
		if err != nil {
			return nil, nil, fmt.Errorf("rotation %d: encode payload: %w", i, err)
		}
		canonical, err := signedRotationEntry(logDID, payload)
		if err != nil {
			return nil, nil, fmt.Errorf("rotation %d: build entry: %w", i, err)
		}

		// 2. Append the on-log leaf: AppendLeaf(EntryIdentity) so the committed leaf
		//    is H(0x00 || SHA256(canonical)) == envelope.OnLogEntryLeafHash(canonical),
		//    the single leaf model every on-log inclusion proof binds against.
		identity := sha256.Sum256(canonical)
		pos, err := tree.AppendLeaf(identity[:])
		if err != nil {
			return nil, nil, err
		}
		effectivePos := types.LogPosition{LogDID: logDID, Sequence: pos}
		positions = append(positions, effectivePos)

		// 3. Grow the tree so the rotation is COVERED (T > P).
		if err := appendFiller(max(fillEach/4, 1), fmt.Sprintf("post%d", i)); err != nil {
			return nil, nil, err
		}

		// 4. The covering head: the REAL RFC-6962 root at the current size, cosigned
		//    by the PRIOR set (eras[i-1]); the inclusion proof reconstructs to it.
		head, err := tree.Head()
		if err != nil {
			return nil, nil, err
		}
		proof, err := tree.InclusionProof(ctx, pos, head.TreeSize)
		if err != nil {
			return nil, nil, fmt.Errorf("rotation %d: inclusion proof: %w", i, err)
		}
		coveringHead, err := eras[i-1].CosignHead(head.TreeSize, head.RootHash, nonZero(0x5A), eras[i-1].N)
		if err != nil {
			return nil, nil, fmt.Errorf("rotation %d: cosign covering head: %w", i, err)
		}

		records = append(records, witness.VerifiedRotationRecord{
			EntryCanonical: canonical,
			EffectivePos:   effectivePos,
			InclusionProof: proof,
			CoveringHead:   coveringHead,
		})
	}

	hist, err := witness.NewVerifiedWitnessSetHistory(eras[0].Set, records)
	if err != nil {
		return nil, nil, fmt.Errorf("NewVerifiedWitnessSetHistory: %w", err)
	}
	return hist, positions, nil
}
