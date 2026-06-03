package main

import (
	"context"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	monitoring "github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/clearcompass-ai/attesta-tools/libs/crosslog"
	jnmon "github.com/clearcompass-ai/attesta-tools/libs/monitoring"
)

const sigPolLogDID = "did:web:state:tn:test"

// genesisSigPolicyRecords is a one-record genesis signature-policy chain with the
// given per-entry floor (ECDSA-only, the JN default scheme set).
func genesisSigPolicyRecords(minSigs uint8) network.SignaturePolicyByPosition {
	return network.SignaturePolicyByPosition{{
		EffectivePos: types.LogPosition{LogDID: sigPolLogDID, Sequence: 0},
		Policy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{0x0001},
			AllowedCosignSchemeTags: []uint8{0x01},
			MinSignaturesPerEntry:   minSigs,
		},
	}}
}

// TestSignaturePolicyJob_FlagsUnderFloorEntry proves the auditor-side floor
// re-check binds: an admitted entry carrying fewer valid signatures than the
// network's min_signatures_per_entry is flagged Critical — the ledger admitted
// something the policy forbids (a gate bypass), exactly the defense-in-depth the
// monitor exists for.
func TestSignaturePolicyJob_FlagsUnderFloorEntry(t *testing.T) {
	// One signature, but the policy floor is 2.
	entry := &envelope.Entry{
		Header: envelope.ControlHeader{SignerDID: "did:key:zJudge"},
		Signatures: []envelope.Signature{
			{SignerDID: "did:key:zJudge", AlgoID: envelope.SigAlgoECDSA},
		},
	}
	src := func(_ context.Context) (jnmon.GovernanceSnapshot, error) {
		return jnmon.GovernanceSnapshot{
			Governance: crosslog.MaterializedGovernance{SignaturePolicies: genesisSigPolicyRecords(2)},
			Entries: []crosslog.EntryAtPosition{
				{Position: types.LogPosition{LogDID: sigPolLogDID, Sequence: 5}, Entry: entry},
			},
			AsOf: types.LogPosition{LogDID: sigPolLogDID, Sequence: 5},
		}, nil
	}

	alerts, err := signaturePolicyJob(src)(context.Background())
	if err != nil {
		t.Fatalf("signaturePolicyJob: %v", err)
	}
	found := false
	for _, a := range alerts {
		if a.Severity == monitoring.Critical && strings.Contains(a.Message, "min_signatures_per_entry") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a Critical under-floor alert, got %d alerts: %v", len(alerts), alerts)
	}
}

// TestSignaturePolicyJob_GenesisOnlyNoFalseAlerts pins the "wired and ready"
// posture: a genesis-only chain with no entries resolves cleanly and raises
// nothing (the steady state before a live on-log scan populates subjects).
func TestSignaturePolicyJob_GenesisOnlyNoFalseAlerts(t *testing.T) {
	src := func(_ context.Context) (jnmon.GovernanceSnapshot, error) {
		return jnmon.GovernanceSnapshot{
			Governance: crosslog.MaterializedGovernance{SignaturePolicies: genesisSigPolicyRecords(1)},
			AsOf:       types.LogPosition{LogDID: sigPolLogDID, Sequence: 0},
		}, nil
	}
	alerts, err := signaturePolicyJob(src)(context.Background())
	if err != nil {
		t.Fatalf("signaturePolicyJob: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("genesis-only wired-and-ready must raise nothing, got %v", alerts)
	}
}
