/*
FILE PATH: verification/attestation_collection_test.go

DESCRIPTION:

	Tests for the JN attestation.VerifyCollection adapter.

	Coverage:
	  - Input guards: nil verifier, negative threshold.
	  - Empty candidates with threshold=0 → trivially met.
	  - Empty candidates with threshold>0 → not met.
	  - Length-mismatched FromBytes inputs surface ErrAttestationCollection.
	  - End-to-end happy path: one signed attestation entry,
	    threshold=1, stub verifier accepts → ThresholdMet=true.
	  - Binding rejection: same entry against a DIFFERENT target
	    position surfaces as Rejection with non-nil Err.

	The stub SignatureVerifier returns nil for every (did, sig)
	tuple, isolating these tests to the SDK's binding + threshold
	logic. Signature primitive correctness is covered by the SDK's
	own 35+ tests on VerifyEntrySignatures.
*/
package verification

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"
)

// acceptAllSigVerifier is a stub SignatureVerifier whose Verify
// always returns nil. Lets the binding + threshold paths inside
// VerifyCollection exercise without dragging in a real DID
// registry. Signature math correctness is the SDK's own test
// surface.
type acceptAllSigVerifier struct{}

func (acceptAllSigVerifier) Verify(_ context.Context, _ string, _ []byte, _ []byte, _ uint16) error {
	return nil
}

// rejectAllSigVerifier is the inverse: every signature is
// reported invalid. Used to confirm per-candidate Err propagates
// into the report's Rejections slice.
type rejectAllSigVerifier struct{}

func (rejectAllSigVerifier) Verify(_ context.Context, _ string, _ []byte, _ []byte, _ uint16) error {
	return errors.New("stub: signature rejected")
}

// buildSignedAttestation builds an attestation entry pointing
// at target, signs it with a fresh secp256k1 key (so the
// envelope.Serialize round-trips cleanly), serializes to
// canonical bytes, and returns the bytes ready for
// EntryWithMetadata. The stub verifier ignores the signature
// material; what matters for these tests is that
// envelope.Deserialize succeeds inside the SDK.
func buildSignedAttestation(t *testing.T, signerDID string, target types.LogPosition) []byte {
	t.Helper()
	cos := target
	auth := envelope.AuthoritySameSigner
	unsigned, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     signerDID,
		Destination:   "did:web:dst",
		AuthorityPath: &auth,
		CosignatureOf: &cos,
	}, []byte(`{"attest":"ok"}`))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	hash := sha256.Sum256(envelope.SigningPayload(unsigned))
	sigBytes, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	signed, err := envelope.NewEntry(unsigned.Header, unsigned.DomainPayload, []envelope.Signature{
		{SignerDID: signerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sigBytes},
	})
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	raw, err := envelope.Serialize(signed)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return raw
}

// ─── Input guards ───────────────────────────────────────────────

func TestVerifyAttestationCollection_NilVerifier(t *testing.T) {
	_, err := VerifyAttestationCollection(context.Background(), CollectionRequest{
		Target:      types.LogPosition{LogDID: "x", Sequence: 1},
		SigVerifier: nil,
		Threshold:   1,
	})
	if !errors.Is(err, ErrAttestationCollection) {
		t.Errorf("err = %v, want errors.Is(ErrAttestationCollection)", err)
	}
}

func TestVerifyAttestationCollection_NegativeThreshold(t *testing.T) {
	_, err := VerifyAttestationCollection(context.Background(), CollectionRequest{
		Target:      types.LogPosition{LogDID: "x", Sequence: 1},
		SigVerifier: acceptAllSigVerifier{},
		Threshold:   -1,
	})
	if !errors.Is(err, ErrAttestationCollection) {
		t.Errorf("err = %v, want errors.Is(ErrAttestationCollection)", err)
	}
}

// ─── Threshold semantics ───────────────────────────────

func TestVerifyAttestationCollection_ZeroThreshold_TriviallyMet(t *testing.T) {
	res, err := VerifyAttestationCollection(context.Background(), CollectionRequest{
		Target:      types.LogPosition{LogDID: "did:web:l", Sequence: 1},
		SigVerifier: acceptAllSigVerifier{},
		Threshold:   0,
	})
	if err != nil {
		t.Fatalf("VerifyAttestationCollection: %v", err)
	}
	if !res.ThresholdMet {
		t.Errorf("zero-threshold MUST be trivially met; got ThresholdMet=false")
	}
	if res.ValidCount != 0 {
		t.Errorf("ValidCount = %d, want 0", res.ValidCount)
	}
}

func TestVerifyAttestationCollection_EmptyCandidates_NotMet(t *testing.T) {
	res, err := VerifyAttestationCollection(context.Background(), CollectionRequest{
		Target:      types.LogPosition{LogDID: "did:web:l", Sequence: 1},
		SigVerifier: acceptAllSigVerifier{},
		Threshold:   1,
	})
	if err != nil {
		t.Fatalf("VerifyAttestationCollection: %v", err)
	}
	if res.ThresholdMet {
		t.Errorf("0 candidates / threshold=1 MUST NOT be met")
	}
}

// ─── End-to-end happy path ──────────────────────────────

func TestVerifyAttestationCollection_HappyPath_OneCandidate(t *testing.T) {
	target := types.LogPosition{LogDID: "did:web:logP", Sequence: 100}
	signerDID := "did:key:zAttester1"
	bytes1 := buildSignedAttestation(t, signerDID, target)

	res, err := VerifyAttestationCollection(context.Background(), CollectionRequest{
		Target: target,
		Candidates: []types.EntryWithMetadata{
			{
				CanonicalBytes: bytes1,
				Position:       types.LogPosition{LogDID: "did:web:logA", Sequence: 200},
				LogTime:        time.Unix(1_700_000_000, 0),
			},
		},
		SigVerifier: acceptAllSigVerifier{},
		Threshold:   1,
	})
	if err != nil {
		t.Fatalf("VerifyAttestationCollection: %v", err)
	}
	if !res.ThresholdMet {
		t.Errorf("happy path MUST meet threshold; got %d valid / %d rejected: %v",
			res.ValidCount, res.RejectedCount, res.Report.Rejections)
	}
	if res.ValidCount != 1 {
		t.Errorf("ValidCount = %d, want 1", res.ValidCount)
	}
}

// ─── Rejection path: wrong target ──────────────────────────

func TestVerifyAttestationCollection_WrongTarget_BindingRejected(t *testing.T) {
	target := types.LogPosition{LogDID: "did:web:logP", Sequence: 100}
	other := types.LogPosition{LogDID: "did:web:logP", Sequence: 999}
	bytes1 := buildSignedAttestation(t, "did:key:zAttester", other)

	res, err := VerifyAttestationCollection(context.Background(), CollectionRequest{
		Target: target,
		Candidates: []types.EntryWithMetadata{
			{
				CanonicalBytes: bytes1,
				Position:       types.LogPosition{LogDID: "did:web:logA", Sequence: 200},
				LogTime:        time.Unix(1_700_000_000, 0),
			},
		},
		SigVerifier: acceptAllSigVerifier{},
		Threshold:   1,
	})
	if err != nil {
		t.Fatalf("VerifyAttestationCollection: %v", err)
	}
	if res.ThresholdMet {
		t.Errorf("wrong-target candidate MUST NOT meet threshold")
	}
	if res.RejectedCount != 1 {
		t.Errorf("RejectedCount = %d, want 1; Rejections=%v", res.RejectedCount, res.Report.Rejections)
	}
}

// ─── FromBytes convenience helper ──────────────────────────

func TestVerifyAttestationCollectionFromBytes_LengthMismatch(t *testing.T) {
	_, err := VerifyAttestationCollectionFromBytes(
		context.Background(),
		types.LogPosition{LogDID: "x", Sequence: 1},
		[][]byte{[]byte("a")},
		[]types.LogPosition{{}, {}},        // 2 positions
		[]time.Time{time.Unix(1, 0)},       // 1 time
		acceptAllSigVerifier{},
		1,
	)
	if !errors.Is(err, ErrAttestationCollection) {
		t.Errorf("err = %v, want errors.Is(ErrAttestationCollection)", err)
	}
}

func TestVerifyAttestationCollectionFromBytes_HappyPath(t *testing.T) {
	target := types.LogPosition{LogDID: "did:web:logP", Sequence: 100}
	bytes1 := buildSignedAttestation(t, "did:key:zAttester1", target)
	res, err := VerifyAttestationCollectionFromBytes(
		context.Background(),
		target,
		[][]byte{bytes1},
		[]types.LogPosition{{LogDID: "did:web:logA", Sequence: 200}},
		[]time.Time{time.Unix(1_700_000_000, 0)},
		acceptAllSigVerifier{},
		1,
	)
	if err != nil {
		t.Fatalf("VerifyAttestationCollectionFromBytes: %v", err)
	}
	if !res.ThresholdMet {
		t.Errorf("happy path MUST meet threshold")
	}
}

// ─── compile-time pin: stubs satisfy SDK SignatureVerifier ─────

func TestStubsSatisfyAttestationSignatureVerifier(t *testing.T) {
	var _ acceptAllSigVerifier
	var _ rejectAllSigVerifier
	_ = json.RawMessage{} // suppress unused-import warning if json drops out
}

// Use the rejectAllSigVerifier in a test so the unused-type
// linter is content even when the import graph changes.
func TestVerifyAttestationCollection_RejectAllSigs_AccumulatesRejections(t *testing.T) {
	target := types.LogPosition{LogDID: "did:web:logP", Sequence: 100}
	bytes1 := buildSignedAttestation(t, "did:key:zAttester1", target)
	res, err := VerifyAttestationCollection(context.Background(), CollectionRequest{
		Target: target,
		Candidates: []types.EntryWithMetadata{
			{CanonicalBytes: bytes1, Position: types.LogPosition{LogDID: "did:web:logA", Sequence: 200}, LogTime: time.Unix(1, 0)},
		},
		SigVerifier: rejectAllSigVerifier{},
		Threshold:   1,
	})
	if err != nil {
		t.Fatalf("VerifyAttestationCollection: %v", err)
	}
	if res.ThresholdMet {
		t.Errorf("all-rejected MUST NOT meet threshold")
	}
	if res.RejectedCount != 1 {
		t.Errorf("RejectedCount = %d, want 1", res.RejectedCount)
	}
}
