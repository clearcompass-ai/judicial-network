/*
FILE PATH: verification/attestation_check_test.go

COVERAGE:
    Every code path in attestation_check.go: nil finder, empty
    entity, finder error, no attestations, every-attestation-stale,
    payload malformed, payload entity-mismatch, untrusted exchange
    (with and without checker), happy path, latest-wins ordering,
    cross-log attestation tie-break by LogTime, trust-check infra
    error.
*/
package verification

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/internal/testutil"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ─── Stubs ──────────────────────────────────────────────────────────

type stubFinder struct {
	entries []*types.EntryWithMetadata
	err     error
}

func (s *stubFinder) FindAttestations(string) ([]*types.EntryWithMetadata, error) {
	return s.entries, s.err
}

type stubTrust struct {
	allow map[string]bool
	err   error
}

func (s *stubTrust) IsTrustedAt(exchangeDID string, _ types.LogPosition) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.allow[exchangeDID], nil
}

// mkAttestationEntry builds + signs a tn-key-attestation-v1 entry
// for the named entity, signed by the named exchange. Returns the
// EntryWithMetadata wrapping its canonical bytes.
func mkAttestationEntry(t *testing.T, entityDID, exchangeDID string, seq uint64, attestationTime int64) *types.EntryWithMetadata {
	t.Helper()
	payload := &schemas.KeyAttestationPayload{
		AttestedEntity:         entityDID,
		AttestedEntityPosition: schemas.SchemaPosition{LogDID: "did:web:l", Sequence: 1},
		GenerationMode:         schemas.GenerationModeClientSideEnclave,
		AttestationTime:        attestationTime,
		WitnessArtifactHash:    "deadbeef",
	}
	body, err := schemas.SerializeKeyAttestation(payload)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	entry, err := builder.BuildCommentary(builder.CommentaryParams{
		Destination: "did:web:exchange.test",
		SignerDID:   exchangeDID,
		Payload:     body,
	})
	if err != nil {
		t.Fatalf("BuildCommentary: %v", err)
	}
	signed := testutil.SignEntry(t, entry, testutil.GenerateSigningKey(t))
	return &types.EntryWithMetadata{
		Position:       types.LogPosition{LogDID: "did:web:l", Sequence: seq},
		CanonicalBytes: envelope.Serialize(signed),
		LogTime:        time.Unix(0, attestationTime*1000),
	}
}

// ─── Argument validation ───────────────────────────────────────────

func TestVerifyKeyAttestation_NilFinder_Errors(t *testing.T) {
	_, err := VerifyKeyAttestation("did:web:e", types.LogPosition{}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "nil finder") {
		t.Errorf("err = %v", err)
	}
}

func TestVerifyKeyAttestation_EmptyEntity_Errors(t *testing.T) {
	_, err := VerifyKeyAttestation("", types.LogPosition{}, &stubFinder{}, nil)
	if err == nil || !strings.Contains(err.Error(), "empty entityDID") {
		t.Errorf("err = %v", err)
	}
}

func TestVerifyKeyAttestation_FinderError_Surfaces(t *testing.T) {
	_, err := VerifyKeyAttestation("did:web:e", types.LogPosition{},
		&stubFinder{err: errors.New("infra")}, nil)
	if err == nil || !strings.Contains(err.Error(), "find") {
		t.Errorf("err = %v", err)
	}
}

// ─── Outcomes ──────────────────────────────────────────────────────

func TestVerifyKeyAttestation_NoAttestation(t *testing.T) {
	res, err := VerifyKeyAttestation("did:web:e", types.LogPosition{}, &stubFinder{}, nil)
	if !errors.Is(err, ErrNoAttestation) {
		t.Errorf("err = %v", err)
	}
	if res.Outcome != AttestationNotFound {
		t.Errorf("Outcome = %v", res.Outcome)
	}
}

func TestVerifyKeyAttestation_Stale(t *testing.T) {
	entity := "did:web:judge"
	entry := mkAttestationEntry(t, entity, "did:web:exchange-A", 50, 1700000000)
	at := types.LogPosition{LogDID: "did:web:l", Sequence: 10} // before seq=50
	res, err := VerifyKeyAttestation(entity, at, &stubFinder{entries: []*types.EntryWithMetadata{entry}}, nil)
	if !errors.Is(err, ErrAttestationStale) {
		t.Errorf("err = %v", err)
	}
	if res.Outcome != AttestationStale {
		t.Errorf("Outcome = %v", res.Outcome)
	}
}

func TestVerifyKeyAttestation_HappyPath_NoTrustChecker(t *testing.T) {
	entity := "did:web:judge"
	entry := mkAttestationEntry(t, entity, "did:web:exchange-A", 50, 1700000000)
	at := types.LogPosition{LogDID: "did:web:l", Sequence: 100}
	res, err := VerifyKeyAttestation(entity, at, &stubFinder{entries: []*types.EntryWithMetadata{entry}}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Outcome != AttestationOK {
		t.Errorf("Outcome = %v", res.Outcome)
	}
	if res.Payload == nil || res.Payload.AttestedEntity != entity {
		t.Errorf("Payload entity wrong: %+v", res.Payload)
	}
}

func TestVerifyKeyAttestation_HappyPath_TrustedExchange(t *testing.T) {
	entity := "did:web:judge"
	exchange := "did:web:exchange-A"
	entry := mkAttestationEntry(t, entity, exchange, 50, 1700000000)
	at := types.LogPosition{LogDID: "did:web:l", Sequence: 100}
	trust := &stubTrust{allow: map[string]bool{exchange: true}}
	res, err := VerifyKeyAttestation(entity, at, &stubFinder{entries: []*types.EntryWithMetadata{entry}}, trust)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Outcome != AttestationOK {
		t.Errorf("Outcome = %v", res.Outcome)
	}
}

func TestVerifyKeyAttestation_UntrustedExchange(t *testing.T) {
	entity := "did:web:judge"
	exchange := "did:web:exchange-rogue"
	entry := mkAttestationEntry(t, entity, exchange, 50, 1700000000)
	at := types.LogPosition{LogDID: "did:web:l", Sequence: 100}
	trust := &stubTrust{allow: map[string]bool{}}
	res, err := VerifyKeyAttestation(entity, at, &stubFinder{entries: []*types.EntryWithMetadata{entry}}, trust)
	if !errors.Is(err, ErrAttestationFromUntrustedExchange) {
		t.Errorf("err = %v", err)
	}
	if res.Outcome != AttestationUntrustedExchange {
		t.Errorf("Outcome = %v", res.Outcome)
	}
	if res.Payload == nil {
		t.Error("payload should still be returned (verifier consumed it)")
	}
}

func TestVerifyKeyAttestation_TrustCheckerInfraError(t *testing.T) {
	entity := "did:web:judge"
	exchange := "did:web:exchange-A"
	entry := mkAttestationEntry(t, entity, exchange, 50, 1700000000)
	at := types.LogPosition{LogDID: "did:web:l", Sequence: 100}
	trust := &stubTrust{err: errors.New("registry down")}
	_, err := VerifyKeyAttestation(entity, at, &stubFinder{entries: []*types.EntryWithMetadata{entry}}, trust)
	if err == nil {
		t.Fatal("expected infra error to surface")
	}
	if errors.Is(err, ErrAttestationFromUntrustedExchange) {
		t.Error("infra error must NOT classify as untrusted")
	}
}

// ─── Latest-wins ordering ──────────────────────────────────────────

func TestVerifyKeyAttestation_LatestWins_SameLog(t *testing.T) {
	entity := "did:web:judge"
	older := mkAttestationEntry(t, entity, "did:web:exchange-A", 50, 1700000000)
	newer := mkAttestationEntry(t, entity, "did:web:exchange-A", 80, 1700001000)
	at := types.LogPosition{LogDID: "did:web:l", Sequence: 100}
	res, err := VerifyKeyAttestation(entity, at,
		&stubFinder{entries: []*types.EntryWithMetadata{older, newer}}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Entry.Position.Sequence != 80 {
		t.Errorf("picked seq=%d, want 80", res.Entry.Position.Sequence)
	}
}

func TestVerifyKeyAttestation_FilterPastQuery(t *testing.T) {
	entity := "did:web:judge"
	pre := mkAttestationEntry(t, entity, "did:web:exchange-A", 50, 1700000000)
	post := mkAttestationEntry(t, entity, "did:web:exchange-A", 200, 1700001000) // after query
	at := types.LogPosition{LogDID: "did:web:l", Sequence: 100}
	res, err := VerifyKeyAttestation(entity, at,
		&stubFinder{entries: []*types.EntryWithMetadata{pre, post}}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Entry.Position.Sequence != 50 {
		t.Errorf("picked seq=%d, want 50 (post=200 must be filtered)", res.Entry.Position.Sequence)
	}
}

func TestVerifyKeyAttestation_NullPosition_NoFilter(t *testing.T) {
	entity := "did:web:judge"
	a := mkAttestationEntry(t, entity, "did:web:exchange-A", 50, 1700000000)
	b := mkAttestationEntry(t, entity, "did:web:exchange-A", 200, 1700001000)
	res, err := VerifyKeyAttestation(entity, types.LogPosition{}, // null
		&stubFinder{entries: []*types.EntryWithMetadata{a, b}}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Entry.Position.Sequence != 200 {
		t.Errorf("null position should not filter; picked seq=%d", res.Entry.Position.Sequence)
	}
}

func TestVerifyKeyAttestation_CrossLog_PicksLatestByLogTime(t *testing.T) {
	entity := "did:web:judge"
	// Two attestations on different logs; pick the one with later LogTime.
	earlier := mkAttestationEntry(t, entity, "did:web:exchange-A", 5, 1700000000)
	earlier.Position.LogDID = "did:web:logA"
	later := mkAttestationEntry(t, entity, "did:web:exchange-A", 5, 1700001000)
	later.Position.LogDID = "did:web:logB"
	res, err := VerifyKeyAttestation(entity, types.LogPosition{},
		&stubFinder{entries: []*types.EntryWithMetadata{earlier, later}}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Entry != later {
		t.Errorf("expected later (LogB) to win; got %+v", res.Entry)
	}
}

// ─── Malformed payloads ────────────────────────────────────────────

func TestVerifyKeyAttestation_PayloadEntityMismatch(t *testing.T) {
	entry := mkAttestationEntry(t, "did:web:OTHER", "did:web:exchange-A", 50, 1700000000)
	at := types.LogPosition{LogDID: "did:web:l", Sequence: 100}
	res, err := VerifyKeyAttestation("did:web:judge", at,
		&stubFinder{entries: []*types.EntryWithMetadata{entry}}, nil)
	if !errors.Is(err, ErrAttestationMalformed) {
		t.Errorf("err = %v", err)
	}
	if res.Outcome != AttestationMalformed {
		t.Errorf("Outcome = %v", res.Outcome)
	}
}

func TestVerifyKeyAttestation_NonDeserializableEntry(t *testing.T) {
	entry := &types.EntryWithMetadata{
		Position:       types.LogPosition{LogDID: "did:web:l", Sequence: 50},
		CanonicalBytes: []byte("not an envelope"),
	}
	at := types.LogPosition{LogDID: "did:web:l", Sequence: 100}
	res, err := VerifyKeyAttestation("did:web:judge", at,
		&stubFinder{entries: []*types.EntryWithMetadata{entry}}, nil)
	if !errors.Is(err, ErrAttestationMalformed) {
		t.Errorf("err = %v", err)
	}
	if res.Outcome != AttestationMalformed {
		t.Errorf("Outcome = %v", res.Outcome)
	}
}

func TestVerifyKeyAttestation_BadPayloadJSON(t *testing.T) {
	// Build a legitimate envelope whose payload is non-JSON. The
	// envelope deserializes; the payload's DeserializeKeyAttestation
	// rejects → AttestationMalformed.
	entry, err := builder.BuildCommentary(builder.CommentaryParams{
		Destination: "did:web:exchange.test",
		SignerDID:   "did:web:exchange-A",
		Payload:     []byte("not json"),
	})
	if err != nil {
		t.Fatalf("BuildCommentary: %v", err)
	}
	signed := testutil.SignEntry(t, entry, testutil.GenerateSigningKey(t))
	wrapped := &types.EntryWithMetadata{
		Position:       types.LogPosition{LogDID: "did:web:l", Sequence: 50},
		CanonicalBytes: envelope.Serialize(signed),
	}
	at := types.LogPosition{LogDID: "did:web:l", Sequence: 100}
	res, err := VerifyKeyAttestation("did:web:judge", at,
		&stubFinder{entries: []*types.EntryWithMetadata{wrapped}}, nil)
	if !errors.Is(err, ErrAttestationMalformed) {
		t.Errorf("err = %v, want ErrAttestationMalformed", err)
	}
	if res.Outcome != AttestationMalformed {
		t.Errorf("Outcome = %v", res.Outcome)
	}
}

func TestVerifyKeyAttestation_NilEntryInSlice_Skipped(t *testing.T) {
	entity := "did:web:judge"
	good := mkAttestationEntry(t, entity, "did:web:exchange-A", 50, 1700000000)
	res, err := VerifyKeyAttestation(entity, types.LogPosition{LogDID: "did:web:l", Sequence: 100},
		&stubFinder{entries: []*types.EntryWithMetadata{nil, good, nil}}, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Outcome != AttestationOK {
		t.Errorf("Outcome = %v", res.Outcome)
	}
}
