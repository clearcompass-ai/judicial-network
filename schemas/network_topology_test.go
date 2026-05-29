// Tests for judicial-network-topology-v1.
//
// Pins the 5-event federation contract:
//   1. Registration in the JN domain Registry.
//   2. Goodlettsville onboarding scenario (anchor_registration).
//   3. COA mirrors Davidson trial (mirror_creation).
//   4. Williamson withdrawal (mirror_revocation).
//   5. Federal-courts network fork (network_fork).
//   6. Davidson drug-court division (scope_division_creation).
//   7. All 5 Action constants round-trip.
//   8. SDK admission.
package schemas

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"
)

func topologyPos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: "did:web:tn-state.example", Sequence: seq}
}

func TestNetworkTopology_RegisteredInJNRegistry(t *testing.T) {
	r := NewRegistry()
	if !r.Has(SchemaNetworkTopologyV1) {
		t.Fatalf("Registry missing %q", SchemaNetworkTopologyV1)
	}
}

func TestNetworkTopology_AnchorRegistration_Goodlettsville(t *testing.T) {
	p := &NetworkTopologyPayload{
		Action:                ActionAnchorRegistration,
		ParentLogDID:          "did:web:tn-state.example",
		AnchorIntervalSeconds: 3600, // hourly for a busy court
		IssuedAt:              time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC),
		IssuingDID:            "did:web:goodlettsville-municipal-court.example",
	}
	body, _ := SerializeNetworkTopologyPayload(p)
	got, err := DeserializeNetworkTopologyPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.AnchorIntervalSeconds != 3600 {
		t.Errorf("AnchorIntervalSeconds drift: %d", got.AnchorIntervalSeconds)
	}
}

func TestNetworkTopology_MirrorCreation_AppellateMirror(t *testing.T) {
	delegationPos := topologyPos(2000) // Davidson's chief-judge delegation entry

	p := &NetworkTopologyPayload{
		Action:           ActionMirrorCreation,
		MirroredLogDID:   "did:web:state:tn:davidson",
		MirroredEntryPos: delegationPos,
		IssuedAt:         time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC),
		IssuingDID:       "did:web:tn-coa.example",
	}
	body, _ := SerializeNetworkTopologyPayload(p)
	got, err := DeserializeNetworkTopologyPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.MirroredEntryPos != delegationPos {
		t.Errorf("MirroredEntryPos drift: %+v", got.MirroredEntryPos)
	}
}

func TestNetworkTopology_MirrorRevocation_WilliamsonExit(t *testing.T) {
	priorMirror := topologyPos(3000)
	p := &NetworkTopologyPayload{
		Action:           ActionMirrorRevocation,
		MirroredLogDID:   "did:web:state:tn:williamson",
		PriorMirrorPos:   priorMirror,
		RevocationReason: "Williamson County withdrew from TN consortium per 2027 reorganization",
		IssuedAt:         time.Date(2027, 7, 1, 11, 0, 0, 0, time.UTC),
		IssuingDID:       "did:web:tn-state.example",
	}
	body, _ := SerializeNetworkTopologyPayload(p)
	got, err := DeserializeNetworkTopologyPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.PriorMirrorPos != priorMirror {
		t.Errorf("PriorMirrorPos drift")
	}
	if got.RevocationReason == "" {
		t.Error("RevocationReason dropped")
	}
}

func TestNetworkTopology_NetworkFork_FederalConsortium(t *testing.T) {
	parentTip := topologyPos(100000)
	p := &NetworkTopologyPayload{
		Action:           ActionNetworkFork,
		ParentNetworkDID: "did:web:tn-state.example",
		ParentTipPos:     parentTip,
		ForkMotivation:   "Federal courts in TN need their own anchor hierarchy per 28 USC § 1404 reform; jurisdictional independence from state federation",
		IssuedAt:         time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC),
		IssuingDID:       "did:web:tn-federal-judicial-conference.example",
	}
	body, _ := SerializeNetworkTopologyPayload(p)
	got, err := DeserializeNetworkTopologyPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.ParentTipPos != parentTip {
		t.Errorf("ParentTipPos drift")
	}
	if got.ForkMotivation == "" {
		t.Error("ForkMotivation dropped")
	}
}

func TestNetworkTopology_ScopeDivisionCreation_DrugCourt(t *testing.T) {
	p := &NetworkTopologyPayload{
		Action:            ActionScopeDivisionCreation,
		ParentExchangeDID: "did:web:state:tn:davidson",
		DivisionName:      "drug court",
		DivisionScope: []string{
			"judicial-criminal-case-v1",
			"controlled-substance-possession",
			"treatment-court-program",
		},
		IssuedAt:   time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC),
		IssuingDID: "did:web:judge.chief.davidson.example",
	}
	body, _ := SerializeNetworkTopologyPayload(p)
	got, err := DeserializeNetworkTopologyPayload(body)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got.DivisionName != "drug court" {
		t.Errorf("DivisionName drift: %q", got.DivisionName)
	}
	if len(got.DivisionScope) != 3 {
		t.Errorf("DivisionScope dropped: %d", len(got.DivisionScope))
	}
}

func TestNetworkTopology_AllActions_RoundTrip(t *testing.T) {
	for _, a := range []string{
		ActionAnchorRegistration,
		ActionMirrorCreation,
		ActionMirrorRevocation,
		ActionNetworkFork,
		ActionScopeDivisionCreation,
	} {
		t.Run(a, func(t *testing.T) {
			p := &NetworkTopologyPayload{
				Action:     a,
				IssuedAt:   time.Now().UTC(),
				IssuingDID: "did:web:test",
			}
			body, _ := SerializeNetworkTopologyPayload(p)
			got, err := DeserializeNetworkTopologyPayload(body)
			if err != nil {
				t.Fatalf("deserialize: %v", err)
			}
			if got.Action != a {
				t.Errorf("Action = %q, want %q", got.Action, a)
			}
		})
	}
}

func TestNetworkTopology_AdmissionThroughSDKRegistry(t *testing.T) {
	r := NewRegistry()
	sdk, err := r.SDKRegistry()
	if err != nil {
		t.Fatalf("SDKRegistry: %v", err)
	}
	p := &NetworkTopologyPayload{
		Action:                ActionAnchorRegistration,
		ParentLogDID:          "did:web:parent",
		AnchorIntervalSeconds: 3600,
		IssuedAt:              time.Now().UTC(),
		IssuingDID:            "did:web:test",
	}
	body, _ := SerializeNetworkTopologyPayload(p)
	if err := r.ValidateAdmission(sdk, SchemaNetworkTopologyV1, &envelope.Entry{DomainPayload: body}); err != nil {
		t.Errorf("admission rejected well-formed payload: %v", err)
	}
}
