// Tests for judicial-crypto-maintenance-v1.
//
// Pins the continuity contract:
//   1. Registration in JN Registry.
//   2. Davidson HSM cert rotation (use case A) round-trips.
//   3. Judge-died M-of-N recovery (use case B) round-trips with
//      ThresholdM/N + ParticipatingDIDs.
//   4. All Action constants round-trip.
//   5. SDK admission.
package schemas

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"
)

func cryptoPos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: "did:web:state:tn:davidson", Sequence: seq}
}

func TestCryptoMaintenance_RegisteredInJNRegistry(t *testing.T) {
	r := NewRegistry()
	if !r.Has(SchemaCryptoMaintenanceV1) {
		t.Fatalf("Registry missing %q", SchemaCryptoMaintenanceV1)
	}
}

// TestCryptoMaintenance_HSMCertRotation_Davidson pins use case A:
// routine institutional key rotation when the clerk's HSM cert
// reaches end-of-life.
func TestCryptoMaintenance_HSMCertRotation_Davidson(t *testing.T) {
	oldTip := cryptoPos(50000) // last entry signed by the old key
	p := &CryptoMaintenancePayload{
		Action:         ActionInstitutionalKeyRotation,
		OutgoingKeyID:  "did:key:zOldClerk2025",
		NewKeyID:       "did:key:zNewClerk2027",
		OldChainTipPos: oldTip,
		IssuedAt:       time.Date(2027, 12, 31, 23, 59, 0, 0, time.UTC),
		IssuingDID:     "did:web:clerk.davidson.example",
	}
	body, _ := SerializeCryptoMaintenancePayload(p)
	got, err := DeserializeCryptoMaintenancePayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.Action != ActionInstitutionalKeyRotation {
		t.Errorf("Action drift: %q", got.Action)
	}
	if got.OutgoingKeyID != "did:key:zOldClerk2025" {
		t.Errorf("OutgoingKeyID drift")
	}
	if got.OldChainTipPos != oldTip {
		t.Errorf("OldChainTipPos drift: %+v", got.OldChainTipPos)
	}
}

// TestCryptoMaintenance_JudgeDied_EscrowRecovery pins use case B:
// the 3-of-5 quorum reconstructs signing capability after a judge
// dies in office.
func TestCryptoMaintenance_JudgeDied_EscrowRecovery(t *testing.T) {
	p := &CryptoMaintenancePayload{
		Action:                ActionMofNEscrowRecoveryExecution,
		ThresholdM:            3,
		ThresholdN:            5,
		ParticipatingDIDs: []string{
			"did:web:judge.chief.davidson.example",
			"did:web:judge.senior1.davidson.example",
			"did:web:judge.senior2.davidson.example",
		},
		RecoveryReason:        "Judge Stevens died in office 2027-06-15; designated 3-of-5 quorum reconstructed signing capacity for 47 pending cases",
		RecoveredPrincipalDID: "did:web:judge.stevens.davidson.example",
		NewKeyID:              "did:key:zRecoveredStevens",
		IssuedAt:              time.Date(2027, 6, 22, 11, 0, 0, 0, time.UTC),
		IssuingDID:            "did:web:judge.chief.davidson.example",
	}
	body, _ := SerializeCryptoMaintenancePayload(p)
	got, err := DeserializeCryptoMaintenancePayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.ThresholdM != 3 || got.ThresholdN != 5 {
		t.Errorf("threshold drift: %d-of-%d", got.ThresholdM, got.ThresholdN)
	}
	if len(got.ParticipatingDIDs) != 3 {
		t.Errorf("ParticipatingDIDs len = %d, want 3 (meets ThresholdM)", len(got.ParticipatingDIDs))
	}
	if got.RecoveredPrincipalDID != "did:web:judge.stevens.davidson.example" {
		t.Errorf("RecoveredPrincipalDID drift")
	}
}

func TestCryptoMaintenance_AllActions_RoundTrip(t *testing.T) {
	for _, a := range []string{
		ActionInstitutionalKeyRotation,
		ActionMofNEscrowRecoveryExecution,
	} {
		t.Run(a, func(t *testing.T) {
			p := &CryptoMaintenancePayload{
				Action:     a,
				IssuedAt:   time.Now().UTC(),
				IssuingDID: "did:web:test",
			}
			body, _ := SerializeCryptoMaintenancePayload(p)
			got, err := DeserializeCryptoMaintenancePayload(body)
			if err != nil {
				t.Fatalf("deserialize: %v", err)
			}
			if got.Action != a {
				t.Errorf("Action = %q, want %q", got.Action, a)
			}
		})
	}
}

func TestCryptoMaintenance_AdmissionThroughSDKRegistry(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	p := &CryptoMaintenancePayload{
		Action:        ActionInstitutionalKeyRotation,
		OutgoingKeyID: "did:key:zOld",
		NewKeyID:      "did:key:zNew",
		IssuedAt:      time.Now().UTC(),
		IssuingDID:    "did:web:test",
	}
	body, _ := SerializeCryptoMaintenancePayload(p)
	if err := r.ValidateAdmission(sdk, SchemaCryptoMaintenanceV1, &envelope.Entry{DomainPayload: body}); err != nil {
		t.Errorf("admission rejected well-formed payload: %v", err)
	}
}
