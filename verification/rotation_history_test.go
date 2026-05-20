package verification

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

const (
	rhSigner = "did:web:vendor.example.gov"
	rhLog    = "did:web:log.example.gov"
	rhDest   = "did:web:dest.example.gov"
)

type fakeSignerQuerier struct{ entries []types.EntryWithMetadata }

func (f fakeSignerQuerier) QueryBySignerDID(context.Context, string) ([]types.EntryWithMetadata, error) {
	return f.entries, nil
}

// makeRotationEntry builds a sequenced rotation EntryWithMetadata: rhSigner's
// key rotates to newKey at `seq`, with the entry signed by signWith (the key
// active just before the rotation — the chain-of-custody signer).
func makeRotationEntry(t *testing.T, newKey []byte, signWith *ecdsa.PrivateKey, seq uint64) types.EntryWithMetadata {
	t.Helper()
	payload, err := verifier.EncodeRotationPayload(verifier.RotationPayload{
		SignerDID:    rhSigner,
		NewPublicKey: newKey,
	})
	if err != nil {
		t.Fatalf("EncodeRotationPayload: %v", err)
	}
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   rhSigner,
		Destination: rhDest,
		EventTime:   int64(seq),
	}, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	digest := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(digest, signWith)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: rhSigner,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	canonical, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return types.EntryWithMetadata{
		CanonicalBytes: canonical,
		Position:       types.LogPosition{LogDID: rhLog, Sequence: seq},
	}
}

func genKeyBytes(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k, signatures.PubKeyBytes(&k.PublicKey)
}

// A valid k0→k1→k2 chain: each rotation signed by the prior key. Build
// returns the records sorted by intrinsic position, and they resolve
// correctly through VerifyKeyAtPosition.
func TestRotationHistorySource_Build_VerifiesChain(t *testing.T) {
	k0, k0b := genKeyBytes(t)
	k1, k1b := genKeyBytes(t)
	_, k2b := genKeyBytes(t)

	// Unsorted input on purpose — Build must sort by position.
	q := fakeSignerQuerier{entries: []types.EntryWithMetadata{
		makeRotationEntry(t, k2b, k1, 20), // k1 -> k2 at seq 20, signed by k1
		makeRotationEntry(t, k1b, k0, 10), // k0 -> k1 at seq 10, signed by k0
	}}
	rhs := &RotationHistorySource{Querier: q}

	recs, err := rhs.Build(context.Background(), rhSigner, k0b)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	if recs[0].EffectivePos.Sequence != 10 || recs[1].EffectivePos.Sequence != 20 {
		t.Fatalf("not sorted: seqs %d, %d", recs[0].EffectivePos.Sequence, recs[1].EffectivePos.Sequence)
	}

	// At seq 15, the active key is k1 (k0->k1 applied at 10; k1->k2 not until 20).
	res, err := verifier.VerifyKeyAtPosition(context.Background(), verifier.KeyAtPositionQuery{
		SignerDID:    rhSigner,
		CandidateKey: k1b,
		QueryPos:     types.LogPosition{LogDID: rhLog, Sequence: 15},
		InitialKey:   k0b,
	}, recs)
	if err != nil {
		t.Fatalf("VerifyKeyAtPosition: %v", err)
	}
	if !res.Active {
		t.Errorf("k1 should be the active key at seq 15 (applied=%d)", res.RotationsApplied)
	}
}

// A forged rotation signed by the RETIRED key (not its predecessor) breaks
// the chain of custody — Build rejects the whole history, fail-closed.
func TestRotationHistorySource_Build_RejectsBrokenChain(t *testing.T) {
	k0, k0b := genKeyBytes(t)
	k1, k1b := genKeyBytes(t)
	_, k2b := genKeyBytes(t)

	q := fakeSignerQuerier{entries: []types.EntryWithMetadata{
		makeRotationEntry(t, k1b, k0, 10), // ok: signed by k0
		makeRotationEntry(t, k2b, k0, 20), // forged: signed by retired k0, must be k1
	}}
	_ = k1
	rhs := &RotationHistorySource{Querier: q}

	if _, err := rhs.Build(context.Background(), rhSigner, k0b); !errors.Is(err, ErrRotationChainBroken) {
		t.Fatalf("err = %v, want ErrRotationChainBroken", err)
	}
}

// Rotations present but no initial key to root the chain → fail closed.
func TestRotationHistorySource_Build_NoInitialKey(t *testing.T) {
	k0, _ := genKeyBytes(t)
	_, k1b := genKeyBytes(t)
	q := fakeSignerQuerier{entries: []types.EntryWithMetadata{makeRotationEntry(t, k1b, k0, 10)}}
	rhs := &RotationHistorySource{Querier: q}
	if _, err := rhs.Build(context.Background(), rhSigner, nil); !errors.Is(err, ErrNoInitialKey) {
		t.Fatalf("err = %v, want ErrNoInitialKey", err)
	}
}

// Non-rotation entries on the same DID are skipped; a DID with no rotation
// entries yields an empty history and no error.
func TestRotationHistorySource_Build_SkipsNonRotation(t *testing.T) {
	k0, k0b := genKeyBytes(t)
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID: rhSigner, Destination: rhDest, EventTime: 1,
	}, []byte(`{"schema_id":"some-other-entry"}`))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	digest := sha256.Sum256(envelope.SigningPayload(entry))
	sig, _ := signatures.SignEntry(digest, k0)
	entry.Signatures = []envelope.Signature{{SignerDID: rhSigner, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
	canonical, _ := envelope.Serialize(entry)

	q := fakeSignerQuerier{entries: []types.EntryWithMetadata{
		{CanonicalBytes: canonical, Position: types.LogPosition{LogDID: rhLog, Sequence: 5}},
	}}
	rhs := &RotationHistorySource{Querier: q}
	recs, err := rhs.Build(context.Background(), rhSigner, k0b)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("non-rotation entries must be skipped; got %d records", len(recs))
	}
}
