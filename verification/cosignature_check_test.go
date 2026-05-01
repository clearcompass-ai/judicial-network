// Tests for CheckCosignature (Phase 3C verifier). Pins every
// closed-set rejection plus the happy paths for filer events
// and pure Signer events.
package verification

import (
	"encoding/json"
	"testing"
	"time"

	davidson "github.com/clearcompass-ai/judicial-network/internal/testfixtures/davidsonlegacy"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// ─── helpers ────────────────────────────────────────────────────────

const (
	exchangeA  = "did:web:state:tn:davidson"
	exchangeB  = "did:web:state:tn:shelby"
	clerkDID   = "did:key:zQ3shCLERK"
	cosigJudge = "did:key:zQ3shJUDGE_COSIG"
	atyDID     = "did:key:zQ3shATTORNEY"
)

func buildResolver(t *testing.T) RoleResolver {
	t.Helper()
	return NewMapRoleResolver().
		Bind(clerkDID, "court_clerk", exchangeA).
		Bind(cosigJudge, "judge", exchangeA)
}

func buildEntry(signerDID string, payload map[string]any, cosignerDIDs ...string) *envelope.Entry {
	body, _ := json.Marshal(payload)
	sigs := []envelope.Signature{{SignerDID: signerDID}}
	for _, c := range cosignerDIDs {
		sigs = append(sigs, envelope.Signature{SignerDID: c})
	}
	return &envelope.Entry{
		Header:        envelope.ControlHeader{SignerDID: signerDID, Destination: exchangeA},
		DomainPayload: body,
		Signatures:    sigs,
	}
}

func attorneyCapacity(role schemas.FilerRole, did string) map[string]any {
	return map[string]any{
		"actor": 2,
		"role":  string(role),
		"did":   did,
		"credentials": map[string]any{
			"bpr_number":   "TN-12345",
			"jurisdiction": "TN",
		},
		"sworn_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// ─── happy paths ────────────────────────────────────────────────────

func TestCheck_HappyPath_AttorneyMotion(t *testing.T) {
	pol := davidson.MustCosignaturePolicy()
	res := buildResolver(t)
	entry := buildEntry(clerkDID, map[string]any{
		"event_type":        "motion_continuance",
		"filed_by_capacity": attorneyCapacity(schemas.FilerRoleDefenseCounsel, atyDID),
	}, atyDID, cosigJudge)

	v := CheckCosignature(entry, pol, res, exchangeA)
	if !v.OK {
		t.Fatalf("expected OK, got rejection=%s reason=%s", v.Rejection, v.Reason)
	}
	if v.Capacity == nil || v.Capacity.DID != atyDID {
		t.Errorf("capacity drift: %+v", v.Capacity)
	}
}

func TestCheck_HappyPath_PureSignerVerdict(t *testing.T) {
	pol := davidson.MustCosignaturePolicy()
	res := buildResolver(t)
	entry := buildEntry(cosigJudge, map[string]any{"event_type": "verdict"})

	v := CheckCosignature(entry, pol, res, exchangeA)
	if !v.OK {
		t.Fatalf("expected OK for verdict (no filer), got: %s %s", v.Rejection, v.Reason)
	}
	if v.Capacity != nil {
		t.Errorf("expected nil capacity for pure-signer event, got: %+v", v.Capacity)
	}
}

// ─── structural rejections ──────────────────────────────────────────

func TestCheck_NilEntry(t *testing.T) {
	v := CheckCosignature(nil, davidson.MustCosignaturePolicy(), buildResolver(t), exchangeA)
	if v.Rejection != CosigRejectMalformedPayload {
		t.Errorf("expected MalformedPayload, got: %s", v.Rejection)
	}
}

func TestCheck_MissingEventType(t *testing.T) {
	entry := buildEntry(cosigJudge, map[string]any{"x": 1})
	v := CheckCosignature(entry, davidson.MustCosignaturePolicy(), buildResolver(t), exchangeA)
	if v.Rejection != CosigRejectMissingEventType {
		t.Errorf("expected MissingEventType, got: %s (%s)", v.Rejection, v.Reason)
	}
}

func TestCheck_UnknownEventType(t *testing.T) {
	entry := buildEntry(cosigJudge, map[string]any{"event_type": "wizard_event"})
	v := CheckCosignature(entry, davidson.MustCosignaturePolicy(), buildResolver(t), exchangeA)
	if v.Rejection != CosigRejectUnknownEventType {
		t.Errorf("expected UnknownEventType, got: %s (%s)", v.Rejection, v.Reason)
	}
}

func TestCheck_MalformedPayload(t *testing.T) {
	entry := &envelope.Entry{
		Header:        envelope.ControlHeader{SignerDID: cosigJudge, Destination: exchangeA},
		DomainPayload: []byte("not json"),
		Signatures:    []envelope.Signature{{SignerDID: cosigJudge}},
	}
	v := CheckCosignature(entry, davidson.MustCosignaturePolicy(), buildResolver(t), exchangeA)
	if v.Rejection != CosigRejectMalformedPayload {
		t.Errorf("expected MalformedPayload, got: %s", v.Rejection)
	}
}

// ─── capacity-presence enforcement ─────────────────────────────────

func TestCheck_CapacityMissingForFilerEvent(t *testing.T) {
	entry := buildEntry(clerkDID, map[string]any{
		"event_type": "motion_continuance",
	}, cosigJudge)
	v := CheckCosignature(entry, davidson.MustCosignaturePolicy(), buildResolver(t), exchangeA)
	if v.Rejection != CosigRejectCapacityMissing {
		t.Errorf("expected CapacityMissing, got: %s (%s)", v.Rejection, v.Reason)
	}
}

func TestCheck_CapacityForbiddenForPureSignerEvent(t *testing.T) {
	entry := buildEntry(cosigJudge, map[string]any{
		"event_type":        "verdict",
		"filed_by_capacity": attorneyCapacity(schemas.FilerRoleDefenseCounsel, atyDID),
	}, atyDID)
	v := CheckCosignature(entry, davidson.MustCosignaturePolicy(), buildResolver(t), exchangeA)
	if v.Rejection != CosigRejectCapacityForbidden {
		t.Errorf("expected CapacityForbidden, got: %s (%s)", v.Rejection, v.Reason)
	}
}

func TestCheck_CapacityInvalidStructurally(t *testing.T) {
	bad := attorneyCapacity(schemas.FilerRoleDefenseCounsel, atyDID)
	bad["actor"] = 1 // ActorSigner instead of ActorFiler
	entry := buildEntry(clerkDID, map[string]any{
		"event_type":        "motion_continuance",
		"filed_by_capacity": bad,
	}, atyDID, cosigJudge)
	v := CheckCosignature(entry, davidson.MustCosignaturePolicy(), buildResolver(t), exchangeA)
	if v.Rejection != CosigRejectCapacityInvalid {
		t.Errorf("expected CapacityInvalid, got: %s (%s)", v.Rejection, v.Reason)
	}
}

// ─── filer-role and filer-signature checks ─────────────────────────

func TestCheck_FilerRoleNotAllowed(t *testing.T) {
	// motion_state_dismissal allows only FilerRoleProsecutor.
	cap := attorneyCapacity(schemas.FilerRoleDefenseCounsel, atyDID)
	entry := buildEntry(clerkDID, map[string]any{
		"event_type":        "motion_state_dismissal",
		"filed_by_capacity": cap,
	}, atyDID, cosigJudge)
	v := CheckCosignature(entry, davidson.MustCosignaturePolicy(), buildResolver(t), exchangeA)
	if v.Rejection != CosigRejectFilerRoleNotAllowed {
		t.Errorf("expected FilerRoleNotAllowed, got: %s (%s)", v.Rejection, v.Reason)
	}
}

func TestCheck_FilerSignatureMissing(t *testing.T) {
	// Capacity claims atyDID but Signatures don't include atyDID.
	entry := buildEntry(clerkDID, map[string]any{
		"event_type":        "motion_continuance",
		"filed_by_capacity": attorneyCapacity(schemas.FilerRoleDefenseCounsel, atyDID),
	}, cosigJudge) // judge cosigns but attorney does NOT
	v := CheckCosignature(entry, davidson.MustCosignaturePolicy(), buildResolver(t), exchangeA)
	if v.Rejection != CosigRejectFilerSigMissing {
		t.Errorf("expected FilerSigMissing, got: %s (%s)", v.Rejection, v.Reason)
	}
}

// ─── cosigner threshold ────────────────────────────────────────────

func TestCheck_InsufficientSigners(t *testing.T) {
	// Attorney cosigns but no Tier 1 cosigner is present.
	entry := buildEntry(clerkDID, map[string]any{
		"event_type":        "motion_continuance",
		"filed_by_capacity": attorneyCapacity(schemas.FilerRoleDefenseCounsel, atyDID),
	}, atyDID)
	// Primary is the Clerk; Phase 3D's AuthorityResolver handles
	// primary; this verifier counts the COSIGNERS only. The
	// motion_continuance rule wants ≥1 cosigner from
	// {court_clerk, judge}; only the attorney cosigned (and the
	// attorney is filtered out as the filer).
	v := CheckCosignature(entry, davidson.MustCosignaturePolicy(), buildResolver(t), exchangeA)
	if v.Rejection != CosigRejectInsufficientSigners {
		t.Errorf("expected InsufficientSigners, got: %s (%s)", v.Rejection, v.Reason)
	}
}

func TestCheck_PersonnelEventRequiresMultipleCosigners(t *testing.T) {
	// judicial_appointment requires ≥2 cosigners. Only one cosigner
	// is present here.
	pol := davidson.MustCosignaturePolicy()
	res := buildResolver(t)
	entry := buildEntry(cosigJudge, map[string]any{
		"event_type": "judicial_appointment",
	}, clerkDID) // only one cosigner; need 2 from {judge, chief_justice}
	v := CheckCosignature(entry, pol, res, exchangeA)
	if v.Rejection != CosigRejectInsufficientSigners {
		t.Errorf("expected InsufficientSigners, got: %s (%s)", v.Rejection, v.Reason)
	}
}

// ─── intra-exchange (Flag #2) ───────────────────────────────────────

func TestCheck_ExchangeMismatch_IntraExchangeRule(t *testing.T) {
	// Cosigners are bound to exchangeA but the verifying exchange
	// is B. motion_continuance is intra-exchange-only.
	res := NewMapRoleResolver().
		Bind(clerkDID, "court_clerk", exchangeA).
		Bind(cosigJudge, "judge", exchangeA)

	entry := buildEntry(clerkDID, map[string]any{
		"event_type":        "motion_continuance",
		"filed_by_capacity": attorneyCapacity(schemas.FilerRoleDefenseCounsel, atyDID),
	}, atyDID, cosigJudge)
	v := CheckCosignature(entry, davidson.MustCosignaturePolicy(), res, exchangeB)
	if v.Rejection != CosigRejectExchangeMismatch {
		t.Errorf("expected ExchangeMismatch, got: %s (%s)", v.Rejection, v.Reason)
	}
}

func TestCheck_CrossExchangeRule_AcceptsCrossExchangeCosigner(t *testing.T) {
	// case_transfer_outbound has IntraExchangeOnly=false, so a
	// cosigner from exchangeA may sign for an event on exchangeB.
	res := NewMapRoleResolver().
		Bind(clerkDID, "court_clerk", exchangeA)

	entry := buildEntry(cosigJudge, map[string]any{
		"event_type": "case_transfer_outbound",
	}, clerkDID)
	v := CheckCosignature(entry, davidson.MustCosignaturePolicy(), res, exchangeB)
	if !v.OK {
		t.Errorf("expected OK (cross-exchange permitted), got: %s (%s)",
			v.Rejection, v.Reason)
	}
}

// ─── credentials ───────────────────────────────────────────────────

func TestCheck_MissingRequiredCredential(t *testing.T) {
	cap := map[string]any{
		"actor": 2,
		"role":  "defense_counsel",
		"did":   atyDID,
		"credentials": map[string]any{
			// bpr_number is missing — required by motion_continuance.
			"jurisdiction": "TN",
		},
		"sworn_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	entry := buildEntry(clerkDID, map[string]any{
		"event_type":        "motion_continuance",
		"filed_by_capacity": cap,
	}, atyDID, cosigJudge)
	v := CheckCosignature(entry, davidson.MustCosignaturePolicy(), buildResolver(t), exchangeA)
	if v.Rejection != CosigRejectMissingCredential {
		t.Errorf("expected MissingCredential, got: %s (%s)", v.Rejection, v.Reason)
	}
}

// (Credential extensibility tests live in cosignature_extensibility_test.go.)
