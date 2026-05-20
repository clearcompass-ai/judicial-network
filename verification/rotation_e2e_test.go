/*
FILE PATH: verification/rotation_e2e_test.go

End-to-end: the secp256k1 keystore PRODUCER → the RotationHistorySource
CONSUMER. Drives the exact production rotation flow — StageNextKey →
canonical EncodeRotationPayload entry → SignEntry with the OLD (still
active) key → CommitRotation — for a two-step k0→k1→k2 chain, then proves
RotationHistorySource projects + chain-verifies it and that
VerifyKeyAtPosition resolves the position-correct key. This is the
load-bearing proof that the producer's old-key-signs output is exactly
what the consumer's authority check accepts.
*/
package verification

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"

	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
)

// produceRotation runs the production producer steps against the keystore:
// stage the next key, build the canonical entry_signer_rotation_v1 entry
// naming it, sign with the RETIRING (currently-active) key, embed, then
// commit. Returns the sequenced entry as the consumer would read it.
func produceRotation(t *testing.T, ks *keystore.MemoryKeyStore, did string, seq uint64) types.EntryWithMetadata {
	t.Helper()
	staged, err := ks.StageNextKey(did, int(seq))
	if err != nil {
		t.Fatalf("StageNextKey: %v", err)
	}
	payload, err := verifier.EncodeRotationPayload(verifier.RotationPayload{
		SignerDID:    did,
		NewPublicKey: staged.PublicKey,
	})
	if err != nil {
		t.Fatalf("EncodeRotationPayload: %v", err)
	}
	entry, err := builder.BuildKeyRotation(builder.KeyRotationParams{
		Destination: rhDest,
		SignerDID:   did,
		TargetRoot:  types.LogPosition{LogDID: rhLog, Sequence: 1},
		Payload:     payload,
		EventTime:   int64(seq),
	})
	if err != nil {
		t.Fatalf("BuildKeyRotation: %v", err)
	}
	// Sign with the OLD key (StageNextKey left it active until commit).
	digest := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := ks.SignEntry(did, digest)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: did,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	canonical, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if _, err := ks.CommitRotation(did); err != nil {
		t.Fatalf("CommitRotation: %v", err)
	}
	return types.EntryWithMetadata{
		CanonicalBytes: canonical,
		Position:       types.LogPosition{LogDID: rhLog, Sequence: seq},
	}
}

func TestRotationProducerToConsumer_E2E(t *testing.T) {
	ks := keystore.NewMemoryKeyStore()
	const did = rhSigner
	info, err := ks.Generate(did, "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	initialKey := info.PublicKey // k0

	// Two real rotations through the producer: k0→k1 @10 (signed by k0),
	// k1→k2 @20 (signed by k1).
	m1 := produceRotation(t, ks, did, 10)
	m2 := produceRotation(t, ks, did, 20)

	// Consumer: project + authority-chain-verify (unsorted input).
	rhs := &RotationHistorySource{
		Querier: fakeSignerQuerier{entries: []types.EntryWithMetadata{m2, m1}},
	}
	recs, err := rhs.Build(context.Background(), did, initialKey)
	if err != nil {
		t.Fatalf("Build (producer→consumer chain): %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	if recs[0].EffectivePos.Sequence != 10 || recs[1].EffectivePos.Sequence != 20 {
		t.Fatalf("not sorted by position: %d, %d", recs[0].EffectivePos.Sequence, recs[1].EffectivePos.Sequence)
	}

	// At seq 15 the active key is the one rotation-1 installed (recs[0]).
	res, err := verifier.VerifyKeyAtPosition(context.Background(), verifier.KeyAtPositionQuery{
		SignerDID:    did,
		CandidateKey: recs[0].NewPublicKey,
		QueryPos:     types.LogPosition{LogDID: rhLog, Sequence: 15},
		InitialKey:   initialKey,
	}, recs)
	if err != nil {
		t.Fatalf("VerifyKeyAtPosition: %v", err)
	}
	if !res.Active {
		t.Errorf("rotation-1 key should be active at seq 15 (applied=%d)", res.RotationsApplied)
	}
}
