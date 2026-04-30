/*
FILE PATH: tests/contracts/cosignature_filing_test.go

DESCRIPTION:
    End-to-end Phase 3C contract tests. Wires together the full
    write+verify lifecycle for an attorney filing under the v1.4
    Event Dictionary's Tier 2 cosignature requirement:

      WRITE  : Clerk + Attorney call delegation.SignAndSubmitCosigned
               with a payload that embeds filed_by_capacity. Two
               signatures land on-log over the same SigningPayload
               digest.

      READ   : verification.CheckCosignature loads the resulting
               envelope from the operator, parses event_type +
               filed_by_capacity, looks up the policy rule, and
               returns OK or a typed rejection.

    Pins the round-trip:
      - Happy path: written entry passes the verifier.
      - Wrong event_type: verifier rejects (closed-set policy).
      - Capacity DID not in cosigners: verifier rejects
        (anti-impersonation).
      - Cross-exchange filing under intra-exchange-only rule:
        verifier rejects (Flag #2).
      - Required credential missing: verifier rejects.

KEY DEPENDENCIES:
    - delegation.SignAndSubmitCosigned (write).
    - verification.CheckCosignature    (read).
    - verification.MapRoleResolver     (DID → role + exchange).
    - policy.MustDavidsonPolicy        (rule fixture).
*/
package contracts

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/delegation"
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/judicial-network/verification"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// ─── helpers ────────────────────────────────────────────────────────

// filingPayload returns a JSON payload with filed_by_capacity for
// the given attorney and a configurable bpr_number / event_type.
func filingPayload(eventType, attorneyDID, bprNumber string) []byte {
	body, _ := json.Marshal(map[string]any{
		"event_type":   eventType,
		"case_ref":     "2027-CV-1234",
		"custom_title": "Motion to Reschedule Hearing",
		"filed_by_capacity": map[string]any{
			"actor": int(schemas.ActorFiler),
			"role":  string(schemas.FilerRoleDefenseCounsel),
			"did":   attorneyDID,
			"credentials": map[string]any{
				"bpr_number":   bprNumber,
				"jurisdiction": "TN",
				"firm":         "Smith & Jones LLP",
			},
			"sworn_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	})
	return body
}

// buildFilingFor wraps the payload in an unsigned envelope with
// SignerDID = clerk.
func buildFilingFor(t *testing.T, clerkDID string, payload []byte) *envelope.Entry {
	t.Helper()
	auth := envelope.AuthoritySameSigner
	header := envelope.ControlHeader{
		Destination:   "did:web:da:davidson-tn",
		SignerDID:     clerkDID,
		AuthorityPath: &auth,
	}
	entry, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	return entry
}

// fixtureWithResolver layers a MapRoleResolver on top of the
// existing contractFixture, binding the Clerk + a sitting Judge
// so CheckCosignature can resolve cosigner roles. Replaces the
// pre-v1.6 directory.Registry plumbing.
func fixtureWithResolver(t *testing.T, clerkDID, judgeDID string) (*contractFixture, verification.RoleResolver) {
	t.Helper()
	f := newFixture(t)
	r := verification.NewMapRoleResolver().
		Bind(clerkDID, "court_clerk", f.institutionalDID).
		Bind(judgeDID, "judge", f.institutionalDID)
	return f, r
}

// ─── happy path: write + verify round-trip ─────────────────────────

func TestCosigFiling_RoundTrip_Verified(t *testing.T) {
	clerkDID := "did:key:zQ3shCLERK"
	judgeDID := "did:key:zQ3shJUDGE_E2E"
	atyDID := "did:key:zQ3shATTORNEY_E2E"

	f, res := fixtureWithResolver(t, clerkDID, judgeDID)
	f.provisionKey(t, clerkDID)
	f.provisionKey(t, judgeDID)
	bindKey(t, f.identity, atyDID)

	entry := buildFilingFor(t, clerkDID,
		filingPayload("motion_continuance", atyDID, "TN-12345"))

	pos, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, entry,
		filingDisplay(atyDID, "TN-12345"), "Filing motion",
		[]string{atyDID, judgeDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}

	// Read it back and verify.
	got := f.envelopeAt(t, pos)
	v := verification.CheckCosignature(got, policy.MustDavidsonPolicy(), res, f.institutionalDID)
	if !v.OK {
		t.Fatalf("verifier rejected round-tripped entry: %s (%s)", v.Rejection, v.Reason)
	}
	if v.Capacity == nil || v.Capacity.DID != atyDID {
		t.Errorf("capacity drift: %+v", v.Capacity)
	}
	if v.EventType != "motion_continuance" {
		t.Errorf("event_type drift: %q", v.EventType)
	}
}

// ─── reject: unknown event_type ────────────────────────────────────

func TestCosigFiling_RejectsUnknownEventType(t *testing.T) {
	clerkDID := "did:key:zQ3shCLERK"
	judgeDID := "did:key:zQ3shJUDGE_E2E"
	atyDID := "did:key:zQ3shATTORNEY_E2E"

	f, res := fixtureWithResolver(t, clerkDID, judgeDID)
	f.provisionKey(t, clerkDID)
	f.provisionKey(t, judgeDID)
	bindKey(t, f.identity, atyDID)

	entry := buildFilingFor(t, clerkDID,
		filingPayload("wizard_motion", atyDID, "TN-12345"))

	pos, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, entry,
		filingDisplay(atyDID, "TN-12345"), "Filing", []string{atyDID, judgeDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}
	got := f.envelopeAt(t, pos)
	v := verification.CheckCosignature(got, policy.MustDavidsonPolicy(), res, f.institutionalDID)
	if v.Rejection != verification.CosigRejectUnknownEventType {
		t.Errorf("expected UnknownEventType, got: %s (%s)", v.Rejection, v.Reason)
	}
}

// ─── reject: capacity DID not in signatures ────────────────────────

// The pipeline cosigners are [judge] but capacity claims aty as the
// filer. Verifier rejects.
func TestCosigFiling_RejectsCapacityDIDImpersonation(t *testing.T) {
	clerkDID := "did:key:zQ3shCLERK"
	judgeDID := "did:key:zQ3shJUDGE_E2E"
	atyDID := "did:key:zQ3shATTORNEY_E2E"

	f, res := fixtureWithResolver(t, clerkDID, judgeDID)
	f.provisionKey(t, clerkDID)
	f.provisionKey(t, judgeDID)
	// Note: atyDID NOT bound on the IdentityProvider — the writer
	// path will not be asked to sign for the attorney either.

	entry := buildFilingFor(t, clerkDID,
		filingPayload("motion_continuance", atyDID, "TN-12345"))

	// Cosigner list does NOT include atyDID; capacity claim is
	// thus unsigned.
	pos, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, entry,
		filingDisplay(atyDID, "TN-12345"), "Filing", []string{judgeDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}
	got := f.envelopeAt(t, pos)
	v := verification.CheckCosignature(got, policy.MustDavidsonPolicy(), res, f.institutionalDID)
	if v.Rejection != verification.CosigRejectFilerSigMissing {
		t.Errorf("expected FilerSigMissing, got: %s (%s)", v.Rejection, v.Reason)
	}
}

// ─── reject: missing required credential ───────────────────────────

func TestCosigFiling_RejectsMissingCredential(t *testing.T) {
	clerkDID := "did:key:zQ3shCLERK"
	judgeDID := "did:key:zQ3shJUDGE_E2E"
	atyDID := "did:key:zQ3shATTORNEY_E2E"

	f, res := fixtureWithResolver(t, clerkDID, judgeDID)
	f.provisionKey(t, clerkDID)
	f.provisionKey(t, judgeDID)
	bindKey(t, f.identity, atyDID)

	// Build a payload whose credentials map omits bpr_number.
	body, _ := json.Marshal(map[string]any{
		"event_type": "motion_continuance",
		"filed_by_capacity": map[string]any{
			"actor": int(schemas.ActorFiler),
			"role":  string(schemas.FilerRoleDefenseCounsel),
			"did":   atyDID,
			"credentials": map[string]any{
				"jurisdiction": "TN", // bpr_number missing
			},
			"sworn_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	})
	entry := buildFilingFor(t, clerkDID, body)

	pos, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, entry,
		filingDisplay(atyDID, ""), "Filing", []string{atyDID, judgeDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}
	got := f.envelopeAt(t, pos)
	v := verification.CheckCosignature(got, policy.MustDavidsonPolicy(), res, f.institutionalDID)
	if v.Rejection != verification.CosigRejectMissingCredential {
		t.Errorf("expected MissingCredential, got: %s (%s)", v.Rejection, v.Reason)
	}
}

// ─── reject: cross-exchange cosigner under intra-exchange-only ─────

// Build the chain on Davidson exchange but verify against Shelby.
// motion_continuance is intra-exchange-only (Flag #2 = true) so
// the verifier should reject.
func TestCosigFiling_IntraExchangeOnly_RejectsCrossExchange(t *testing.T) {
	clerkDID := "did:key:zQ3shCLERK"
	judgeDID := "did:key:zQ3shJUDGE_E2E"
	atyDID := "did:key:zQ3shATTORNEY_E2E"

	f, res := fixtureWithResolver(t, clerkDID, judgeDID)
	f.provisionKey(t, clerkDID)
	f.provisionKey(t, judgeDID)
	bindKey(t, f.identity, atyDID)

	entry := buildFilingFor(t, clerkDID,
		filingPayload("motion_continuance", atyDID, "TN-12345"))
	pos, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, entry,
		filingDisplay(atyDID, "TN-12345"), "Filing", []string{atyDID, judgeDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}

	// Verify under a DIFFERENT exchange DID.
	got := f.envelopeAt(t, pos)
	otherExchange := "did:web:da:shelby-tn"
	v := verification.CheckCosignature(got, policy.MustDavidsonPolicy(), res, otherExchange)
	if v.Rejection != verification.CosigRejectExchangeMismatch {
		t.Errorf("expected ExchangeMismatch, got: %s (%s)", v.Rejection, v.Reason)
	}
}
