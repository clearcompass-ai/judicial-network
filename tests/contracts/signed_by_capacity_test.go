/*
FILE PATH: tests/contracts/signed_by_capacity_test.go

DESCRIPTION:
    Phase 3D.signed-by end-to-end contract tests. Pins the
    payload-symmetry guarantee: a writer who embeds
    `signed_by_capacities` alongside `filed_by_capacity` produces
    an entry that the verifier can validate WITHOUT any external
    role-lookup state — just PayloadRoleResolver reading the entry's
    own bytes.

    Why this matters: pre-3D.signed-by, the verifier needed an
    off-log directory.OfficerRegistry (deleted in 3D.cleanup-1) or a
    test-only MapRoleResolver to map cosigner DID → role + exchange.
    With signed_by_capacities embedded in the payload, the on-log
    bytes ARE the truth. No registry; no shared mutable state. The
    aggregator (Phase 3E) reads it; the verifier reads it; both see
    the same source.

    Pins the round-trip:
      - Happy path: writer embeds signed_by_capacities; verifier
        succeeds with PayloadRoleResolver as the only role source.
      - Cosigner not declared in signed_by_capacities: verifier
        rejects (InsufficientSigners — the unknown DID does not
        count toward the threshold).
      - Cosigner declared but from the wrong exchange under an
        intra-exchange-only rule: verifier rejects with
        ExchangeMismatch.

KEY DEPENDENCIES:
    - delegation.SignAndSubmitCosigned (write).
    - verification.PayloadRoleResolver  (production resolver).
    - verification.CheckCosignature     (read).
    - policy.MustDavidsonPolicy         (rule fixture).
*/
package contracts

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/delegation"
	davidson "github.com/clearcompass-ai/judicial-network/deployments/davidson_county/rules"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// ─── helpers ────────────────────────────────────────────────────────

// signedByCapacityFiling builds a motion_continuance payload that
// embeds BOTH filed_by_capacity (the attorney's claim) AND
// signed_by_capacities (the judge's self-description). The judge is
// the only cosigning Signer; clerk is the primary signer at
// Signatures[0] (skipped by the verifier) and the attorney is the
// filer (described in filed_by_capacity, also skipped).
func signedByCapacityFiling(
	atyDID, judgeDID, judgeExchange, bprNumber string,
) []byte {
	body, _ := json.Marshal(map[string]any{
		"event_type":   "motion_continuance",
		"case_ref":     "2027-CV-1234",
		"custom_title": "Motion to Reschedule Hearing",
		"filed_by_capacity": map[string]any{
			"actor": int(schemas.ActorFiler),
			"role":  string(schemas.FilerRoleDefenseCounsel),
			"did":   atyDID,
			"credentials": map[string]any{
				"bpr_number":   bprNumber,
				"jurisdiction": "TN",
				"firm":         "Smith & Jones LLP",
			},
			"sworn_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
		"signed_by_capacities": []map[string]any{
			{
				"did":      judgeDID,
				"role":     "judge",
				"exchange": judgeExchange,
			},
		},
	})
	return body
}

// ─── happy path ─────────────────────────────────────────────────────

// TestSignedByCapacity_RoundTrip pins the payload-symmetry promise:
// a writer that embeds signed_by_capacities + filed_by_capacity
// produces an entry whose cosignature check succeeds with
// PayloadRoleResolver as the only source of cosigner role/exchange
// data — no MapRoleResolver, no off-log registry.
func TestSignedByCapacity_RoundTrip(t *testing.T) {
	clerkDID := "did:key:zQ3shCLERK"
	judgeDID := "did:key:zQ3shJUDGE_SBC"
	atyDID := "did:key:zQ3shATTORNEY_SBC"

	f := newFixture(t)
	f.provisionKey(t, clerkDID)
	f.provisionKey(t, judgeDID)
	bindKey(t, f.identity, atyDID)

	payload := signedByCapacityFiling(atyDID, judgeDID, f.institutionalDID, "TN-12345")
	entry := buildFilingFor(t, clerkDID, payload)

	pos, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, entry,
		filingDisplay(atyDID, "TN-12345"), "Filing motion",
		[]string{atyDID, judgeDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}

	got := f.envelopeAt(t, pos)

	// Build the resolver from the on-log payload. NOTHING
	// preconfigured externally.
	res, err := verification.NewPayloadRoleResolver(got.DomainPayload)
	if err != nil {
		t.Fatalf("NewPayloadRoleResolver: %v", err)
	}

	v := verification.CheckCosignature(got, davidson.MustCosignaturePolicy(), res, f.institutionalDID)
	if !v.OK {
		t.Fatalf("verifier rejected payload-resolver entry: %s (%s)", v.Rejection, v.Reason)
	}
	if v.Capacity == nil || v.Capacity.DID != atyDID {
		t.Errorf("capacity drift: %+v", v.Capacity)
	}
	if v.EventType != "motion_continuance" {
		t.Errorf("event_type drift: %q", v.EventType)
	}

	// Round-trip the resolver too: it should expose the parsed cap.
	caps := res.Capacities()
	if len(caps) != 1 {
		t.Fatalf("expected 1 signed_by_capacity, got %d", len(caps))
	}
	if caps[0].DID != judgeDID {
		t.Errorf("did drift: %q", caps[0].DID)
	}
	if caps[0].Role != "judge" {
		t.Errorf("role drift: %q", caps[0].Role)
	}
	if caps[0].Exchange != f.institutionalDID {
		t.Errorf("exchange drift: %q", caps[0].Exchange)
	}
}

// ─── reject: cosigner not declared in signed_by_capacities ─────────

// The judge cosigns the entry (Signatures[2]) but the writer forgot
// to declare them in signed_by_capacities. PayloadRoleResolver
// returns ErrSignerUnknown; the verifier surfaces this as
// InsufficientSigners (the judge does not count toward the threshold).
func TestSignedByCapacity_RejectsUndeclaredCosigner(t *testing.T) {
	clerkDID := "did:key:zQ3shCLERK"
	judgeDID := "did:key:zQ3shJUDGE_SBC"
	atyDID := "did:key:zQ3shATTORNEY_SBC"

	f := newFixture(t)
	f.provisionKey(t, clerkDID)
	f.provisionKey(t, judgeDID)
	bindKey(t, f.identity, atyDID)

	// Build a payload with EMPTY signed_by_capacities.
	payload, _ := json.Marshal(map[string]any{
		"event_type": "motion_continuance",
		"case_ref":   "2027-CV-1234",
		"filed_by_capacity": map[string]any{
			"actor": int(schemas.ActorFiler),
			"role":  string(schemas.FilerRoleDefenseCounsel),
			"did":   atyDID,
			"credentials": map[string]any{
				"bpr_number":   "TN-12345",
				"jurisdiction": "TN",
			},
			"sworn_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
		// signed_by_capacities omitted entirely.
	})
	entry := buildFilingFor(t, clerkDID, payload)

	pos, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, entry,
		filingDisplay(atyDID, "TN-12345"), "Filing motion",
		[]string{atyDID, judgeDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}

	got := f.envelopeAt(t, pos)
	res, err := verification.NewPayloadRoleResolver(got.DomainPayload)
	if err != nil {
		t.Fatalf("NewPayloadRoleResolver: %v", err)
	}
	v := verification.CheckCosignature(got, davidson.MustCosignaturePolicy(), res, f.institutionalDID)
	if v.Rejection != verification.CosigRejectInsufficientSigners {
		t.Errorf("expected InsufficientSigners (judge undeclared), got: %s (%s)",
			v.Rejection, v.Reason)
	}
}

// ─── reject: cosigner declared with wrong exchange ─────────────────

// The judge cosigns and is in signed_by_capacities, but the writer
// declared their exchange as a different jurisdiction. The
// motion_continuance rule has IntraExchangeOnly=true, so the
// verifier rejects.
func TestSignedByCapacity_RejectsWrongExchangeDeclaration(t *testing.T) {
	clerkDID := "did:key:zQ3shCLERK"
	judgeDID := "did:key:zQ3shJUDGE_SBC"
	atyDID := "did:key:zQ3shATTORNEY_SBC"

	f := newFixture(t)
	f.provisionKey(t, clerkDID)
	f.provisionKey(t, judgeDID)
	bindKey(t, f.identity, atyDID)

	// Capacity declares the judge as belonging to a different
	// exchange than the entry's destination.
	wrongExchange := "did:web:da:shelby-tn"
	payload := signedByCapacityFiling(atyDID, judgeDID, wrongExchange, "TN-12345")
	entry := buildFilingFor(t, clerkDID, payload)

	pos, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, entry,
		filingDisplay(atyDID, "TN-12345"), "Filing motion",
		[]string{atyDID, judgeDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}

	got := f.envelopeAt(t, pos)
	res, err := verification.NewPayloadRoleResolver(got.DomainPayload)
	if err != nil {
		t.Fatalf("NewPayloadRoleResolver: %v", err)
	}
	v := verification.CheckCosignature(got, davidson.MustCosignaturePolicy(), res, f.institutionalDID)
	if v.Rejection != verification.CosigRejectExchangeMismatch {
		t.Errorf("expected ExchangeMismatch, got: %s (%s)", v.Rejection, v.Reason)
	}
}

// ─── reject: malformed signed_by_capacities block ──────────────────

// An entry whose payload has signed_by_capacities present but
// malformed should fail at PayloadRoleResolver construction. The
// caller surfaces the error before even invoking CheckCosignature.
func TestSignedByCapacity_MalformedBlockSurfacesAtCtor(t *testing.T) {
	bad := []byte(`{"event_type":"motion_continuance","signed_by_capacities":"not-an-array"}`)
	_, err := verification.NewPayloadRoleResolver(bad)
	if err == nil {
		t.Fatal("expected ctor error on malformed block")
	}
}
