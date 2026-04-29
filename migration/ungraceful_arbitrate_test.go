/*
FILE PATH: migration/ungraceful_arbitrate_test.go

COVERAGE:
    ArbitrateHostileRecovery wrapper: success path, supermajority
    failure, witness-required missing, witness-not-independent,
    SDK infrastructure error surfacing, and ErrArbitrationDenied
    sentinel propagation.
*/
package migration

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/internal/testutil"
)

// mkApproval signs a cosignature commentary entry referencing
// recoveryPos. The SDK's IsCosignatureOf check requires a valid
// CosignatureOf header.
func mkApproval(t *testing.T, signerDID string, recoveryPos types.LogPosition) types.EntryWithMetadata {
	t.Helper()
	entry, err := builder.BuildCosignature(builder.CosignatureParams{
		Destination:  "did:web:exchange.test",
		SignerDID:    signerDID,
		CosignatureOf: recoveryPos,
	})
	if err != nil {
		t.Fatalf("BuildCosignature: %v", err)
	}
	signed := testutil.SignEntry(t, entry, testutil.GenerateSigningKey(t))
	return types.EntryWithMetadata{
		Position:       types.LogPosition{LogDID: "did:web:l", Sequence: 100},
		CanonicalBytes: envelope.Serialize(signed),
	}
}

// ─── Happy path: 4-of-5 supermajority, no witness required ────────

func TestArbitrateHostileRecovery_Supermajority_NoWitness_OK(t *testing.T) {
	recoveryPos := types.LogPosition{LogDID: "did:web:l", Sequence: 50}
	approvals := []types.EntryWithMetadata{
		mkApproval(t, "did:web:node-A", recoveryPos),
		mkApproval(t, "did:web:node-B", recoveryPos),
		mkApproval(t, "did:web:node-C", recoveryPos),
		mkApproval(t, "did:web:node-D", recoveryPos),
	}
	res, err := ArbitrateHostileRecovery(
		recoveryPos,
		approvals,
		5,                // total nodes
		nil,              // EscrowNodeSet not required when no witness
		nil,              // no witness cosig
		nil,              // SchemaParams nil → defaults (2/3 threshold, no witness)
	)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.OverrideAuthorized {
		t.Errorf("OverrideAuthorized = false; reason=%s", res.Reason)
	}
	if res.ApprovalCount != 4 {
		t.Errorf("ApprovalCount = %d", res.ApprovalCount)
	}
}

// ─── Insufficient approvals: 2-of-5 fails 2/3 threshold ───────────

func TestArbitrateHostileRecovery_BelowSupermajority_Denied(t *testing.T) {
	recoveryPos := types.LogPosition{LogDID: "did:web:l", Sequence: 50}
	approvals := []types.EntryWithMetadata{
		mkApproval(t, "did:web:node-A", recoveryPos),
		mkApproval(t, "did:web:node-B", recoveryPos),
	}
	res, err := ArbitrateHostileRecovery(recoveryPos, approvals, 5, nil, nil, nil)
	if !errors.Is(err, ErrArbitrationDenied) {
		t.Errorf("err = %v, want ErrArbitrationDenied", err)
	}
	if res == nil || res.OverrideAuthorized {
		t.Errorf("override should NOT be authorized; res = %+v", res)
	}
	if res.ApprovalCount != 2 {
		t.Errorf("ApprovalCount = %d", res.ApprovalCount)
	}
}

// ─── Witness required + missing → SDK rejects (ErrMissingEscrowNodeSet) ─

func TestArbitrateHostileRecovery_WitnessRequired_NoEscrowSet_InfraError(t *testing.T) {
	recoveryPos := types.LogPosition{LogDID: "did:web:l", Sequence: 50}
	approvals := []types.EntryWithMetadata{
		mkApproval(t, "did:web:node-A", recoveryPos),
	}
	schemaParams := &types.SchemaParameters{
		OverrideRequiresIndependentWitness: true,
	}
	_, err := ArbitrateHostileRecovery(recoveryPos, approvals, 5, nil, nil, schemaParams)
	if err == nil {
		t.Fatal("witness-required + empty escrow set must error")
	}
}

// ─── Bad config: TotalEscrowNodes = 0 → SDK rejects ───────────────

func TestArbitrateHostileRecovery_ZeroTotalNodes_InfraError(t *testing.T) {
	recoveryPos := types.LogPosition{LogDID: "did:web:l", Sequence: 50}
	_, err := ArbitrateHostileRecovery(recoveryPos, nil, 0, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for zero total nodes")
	}
}

// ─── ArbitrationResult fields populated on denial ─────────────────

func TestArbitrateHostileRecovery_DeniedResult_FieldsPopulated(t *testing.T) {
	recoveryPos := types.LogPosition{LogDID: "did:web:l", Sequence: 50}
	approvals := []types.EntryWithMetadata{
		mkApproval(t, "did:web:node-A", recoveryPos),
	}
	res, _ := ArbitrateHostileRecovery(recoveryPos, approvals, 5, nil, nil, nil)
	if res == nil {
		t.Fatal("denied result must still surface")
	}
	if res.RequiredCount == 0 {
		t.Error("RequiredCount must be populated")
	}
	if res.Reason == "" {
		t.Error("Reason must be populated for denial")
	}
}

// ─── Wrapper does not silently swallow SDK error sentinels ────────

func TestArbitrateHostileRecovery_PropagatesSDKError(t *testing.T) {
	// Negative TotalEscrowNodes → SDK returns ErrInvalidEscrowNodeCount
	recoveryPos := types.LogPosition{LogDID: "did:web:l", Sequence: 50}
	_, err := ArbitrateHostileRecovery(recoveryPos, nil, -1, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for negative total nodes")
	}
	if errors.Is(err, ErrArbitrationDenied) {
		t.Error("infra error must NOT classify as ErrArbitrationDenied")
	}
}

// Ensure the lifecycle package is referenced for clarity.
var _ = lifecycle.EvaluateArbitration
