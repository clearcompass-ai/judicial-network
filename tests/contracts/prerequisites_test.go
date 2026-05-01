/*
FILE PATH: tests/contracts/prerequisites_test.go

DESCRIPTION:
    Phase 3D.preqs end-to-end contract tests. Wires the v1.6
    closed-set vocabulary + prerequisite policy into the existing
    write/verify pipeline:

      WRITE  : SignAndSubmitCosigned lands a motion entry with
               filed_by_capacity + signed_by_capacities.
      READ   : verification.CheckCosignature passes (Phase 3C/3D
               surfaces).
      PREREQ : prerequisites.Walker.Check(eventType, ctx) gates the
               entry against the case-root subtree state. CaseContext
               is hand-built from "what the aggregator would observe"
               so the gate is independent of the SMT walk.

    Pins:
      - Round-trip: motion_continuance with case_initiated ancestor
        passes BOTH the cosignature check AND the prereq walk.
      - Vocabulary: an unknown event_type is rejected at the prereq
        gate even when the cosignature check happens to allow it.
      - Hard ancestor missing: motion_continuance without
        case_initiated is rejected with WalkRejectMissingAncestor.
      - Authority gate: judicial_appointment requires the right
        scope; missing scope rejects with WalkRejectMissingAuthority.
      - Advisory rule: transcript_publication without a hearing
        ancestor surfaces an Advisory violation but still PASSES.
*/
package contracts

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/delegation"
	davidson "github.com/clearcompass-ai/judicial-network/internal/testfixtures/davidsonlegacy"
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// ─── helpers ────────────────────────────────────────────────────────

// motionPayload builds a motion_continuance payload that carries
// both filed_by_capacity (Tier 2 attorney) and signed_by_capacities
// (the cosigning judge). Matches the writer pattern used elsewhere
// in tests/contracts; we just bring the prereq walker into scope
// to gate the same entry through the new surface.
func motionPayload(atyDID, judgeDID, judgeExchange, bprNumber string) []byte {
	body, _ := json.Marshal(map[string]any{
		"event_type": "motion_continuance",
		"case_ref":   "2027-CV-1234",
		"filed_by_capacity": map[string]any{
			"actor": int(schemas.ActorFiler),
			"role":  string(schemas.FilerRoleDefenseCounsel),
			"did":   atyDID,
			"credentials": map[string]any{
				"bpr_number":   bprNumber,
				"jurisdiction": "TN",
			},
			"sworn_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
		"signed_by_capacities": []map[string]any{
			{"did": judgeDID, "role": "judge", "exchange": judgeExchange},
		},
	})
	return body
}

// ─── happy path: cosignature + prereq both pass ────────────────────

func TestPrereqs_RoundTrip_GatesEntry(t *testing.T) {
	clerkDID := "did:key:zQ3shCLERK"
	judgeDID := "did:key:zQ3shJUDGE_PRQ"
	atyDID := "did:key:zQ3shATTORNEY_PRQ"

	f := newFixture(t)
	f.provisionKey(t, clerkDID)
	f.provisionKey(t, judgeDID)
	bindKey(t, f.identity, atyDID)

	entry := buildFilingFor(t, clerkDID,
		motionPayload(atyDID, judgeDID, f.institutionalDID, "TN-12345"))
	pos, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, entry,
		filingDisplay(atyDID, "TN-12345"), "Filing motion",
		[]string{atyDID, judgeDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}
	got := f.envelopeAt(t, pos)

	// Cosignature gate (already covered elsewhere; repeated here to
	// pin the e2e flow).
	res, err := verification.NewPayloadRoleResolver(got.DomainPayload)
	if err != nil {
		t.Fatalf("NewPayloadRoleResolver: %v", err)
	}
	cv := verification.CheckCosignature(got, davidson.MustCosignaturePolicy(),
		res, f.institutionalDID)
	if !cv.OK {
		t.Fatalf("cosig rejected: %s (%s)", cv.Rejection, cv.Reason)
	}

	// Prereq gate.
	w := &prerequisites.Walker{Policy: davidson.MustPrerequisitePolicy()}
	pv := w.Check("motion_continuance", prerequisites.CaseContext{
		CaseRef:        "2027-CV-1234",
		ObservedEvents: []string{"case_initiated"},
	})
	if !pv.OK {
		t.Fatalf("prereq rejected: %s (%s)", pv.Rejection, pv.Reason)
	}
}

// ─── vocabulary gate: unknown event rejected ───────────────────────

func TestPrereqs_VocabularyGate_RejectsUnknownEvent(t *testing.T) {
	w := &prerequisites.Walker{Policy: davidson.MustPrerequisitePolicy()}
	v := w.Check("wizard_motion", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"}, // doesn't matter
	})
	if v.OK {
		t.Fatal("vocabulary gate must reject unknown events")
	}
	if v.Rejection != prerequisites.WalkRejectUnknownEvent {
		t.Errorf("Rejection=%s", v.Rejection)
	}
}

// ─── ancestor gate: motion without case_initiated rejected ─────────

func TestPrereqs_AncestorGate_RejectsMissingCaseInit(t *testing.T) {
	w := &prerequisites.Walker{Policy: davidson.MustPrerequisitePolicy()}
	v := w.Check("motion_continuance", prerequisites.CaseContext{
		CaseRef:        "2027-CV-9999",
		ObservedEvents: []string{}, // case_initiated missing
	})
	if v.OK {
		t.Fatal("must reject motion without case_initiated")
	}
	if v.Rejection != prerequisites.WalkRejectMissingAncestor {
		t.Errorf("Rejection=%s", v.Rejection)
	}
	if len(v.Hard) != 1 {
		t.Errorf("expected 1 Hard violation, got %d", len(v.Hard))
	}
}

// ─── authority gate: judicial_appointment requires scope ───────────

func TestPrereqs_AuthorityGate_RejectsWithoutScope(t *testing.T) {
	w := &prerequisites.Walker{Policy: davidson.MustPrerequisitePolicy()}
	v := w.Check("judicial_appointment", prerequisites.CaseContext{
		PrimaryAuthorityScopes: []string{"unrelated_scope"},
	})
	if v.OK {
		t.Fatal("must reject without judicial_appointment_authority")
	}
	if v.Rejection != prerequisites.WalkRejectMissingAuthority {
		t.Errorf("Rejection=%s", v.Rejection)
	}
}

func TestPrereqs_AuthorityGate_AcceptsWithScope(t *testing.T) {
	w := &prerequisites.Walker{Policy: davidson.MustPrerequisitePolicy()}
	v := w.Check("judicial_appointment", prerequisites.CaseContext{
		PrimaryAuthorityScopes: []string{"judicial_appointment_authority"},
	})
	if !v.OK {
		t.Fatalf("must accept with scope: %+v", v)
	}
}

// ─── advisory: hearing missing surfaces note but does NOT block ────

func TestPrereqs_AdvisoryRule_DoesNotBlock(t *testing.T) {
	w := &prerequisites.Walker{Policy: davidson.MustPrerequisitePolicy()}
	v := w.Check("transcript_publication", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"}, // hearing absent
	})
	if !v.OK {
		t.Errorf("advisory must NOT block: %+v", v)
	}
	if len(v.Advisory) != 1 {
		t.Errorf("expected 1 Advisory violation, got %d", len(v.Advisory))
	}
	if len(v.Hard) != 0 {
		t.Errorf("expected 0 Hard violations, got %d", len(v.Hard))
	}
}

// ─── verdict: requires merits posture ──────────────────────────────

// case_initiated alone is NOT enough for a verdict; the dictionary
// requires a merits-posture event in the subtree.
func TestPrereqs_Verdict_RejectsWithoutMeritsPosture(t *testing.T) {
	w := &prerequisites.Walker{Policy: davidson.MustPrerequisitePolicy()}
	v := w.Check("verdict", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if v.OK {
		t.Fatal("verdict must require merits-posture ancestor")
	}
	if v.Rejection != prerequisites.WalkRejectMissingAncestor {
		t.Errorf("Rejection=%s", v.Rejection)
	}
}

func TestPrereqs_Verdict_AcceptsWithMeritsPosture(t *testing.T) {
	w := &prerequisites.Walker{Policy: davidson.MustPrerequisitePolicy()}
	v := w.Check("verdict", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated", "responsive_pleading"},
	})
	if !v.OK {
		t.Errorf("verdict with merits posture must be OK: %+v", v)
	}
}

// ─── cross-exchange events: no prereqs ─────────────────────────────

// case_transfer_outbound, case_transfer_inbound, relay_attestation
// are bootstrap-friendly per the v1.6 dictionary; the prereq policy
// has zero rules for them.
func TestPrereqs_CrossExchangeEvents_NoPrereqs(t *testing.T) {
	w := &prerequisites.Walker{Policy: davidson.MustPrerequisitePolicy()}
	for _, evt := range []string{
		"case_transfer_outbound",
		"case_transfer_inbound",
		"relay_attestation",
	} {
		v := w.Check(evt, prerequisites.CaseContext{})
		if !v.OK {
			t.Errorf("%s must pass with no prereqs: %+v", evt, v)
		}
	}
}
