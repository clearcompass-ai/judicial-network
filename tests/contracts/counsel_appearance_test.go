/*
FILE PATH: tests/contracts/counsel_appearance_test.go

DESCRIPTION:

	End-to-end functional contract tests for the v1.8 §1
	counsel_appearance event. Wires together the full
	write+verify lifecycle:

	  WRITE  : Clerk + Attorney call delegation.SignAndSubmitCosigned
	           with the payload schemas/counsel_appearance encodes.

	  READ   : verification.CheckCosignature loads the envelope,
	           extracts filed_by_capacity, looks up the cosig
	           rule in the TN trial fixture (via tn/counties/
	           davidson composer), and returns OK or a typed
	           rejection.

	Pins the round-trip:
	  - Defense counsel files; clerk cosigns; verifier passes.
	  - Civil attorney files; clerk cosigns; verifier passes.
	  - Prosecutor files (e.g., notice of substitution); verifier
	    passes.
	  - Fiduciary cannot file counsel_appearance (closed Filer set).
	  - bpr_number missing → verifier rejects.

KEY DEPENDENCIES:
  - delegation.SignAndSubmitCosigned (write).
  - verification.CheckCosignature    (read).
  - tn/trial.MustCosignaturePolicy   (rule fixture).
*/
package contracts

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/judicial-network/api/exchange/identity"
	"github.com/clearcompass-ai/judicial-network/delegation"
	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// ─── helpers ────────────────────────────────────────────────────────

// counselAppearancePayload returns a JSON payload for a
// counsel_appearance event with filed_by_capacity stamped for
// the given attorney role + bpr_number.
func counselAppearancePayload(attorneyDID, bprNumber string,
	role schemas.FilerRole, represents []string) []byte {
	body, _ := json.Marshal(map[string]any{
		"event_type":    "counsel_appearance",
		"appearance_id": "ap-001",
		"attorney_did":  attorneyDID,
		"represents":    represents,
		"case_ref":      "DAV-2027-CR-0042",
		"status":        "active",
		"filed_by_capacity": map[string]any{
			"actor": int(schemas.ActorFiler),
			"role":  string(role),
			"did":   attorneyDID,
			"credentials": map[string]any{
				"bpr_number":   bprNumber,
				"jurisdiction": "TN",
			},
			"sworn_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	})
	return body
}

// counselAppearanceEnvelope wraps the payload in an unsigned
// envelope addressed to Davidson, signed by the clerk.
func counselAppearanceEnvelope(t *testing.T, clerkDID string, payload []byte) *envelope.Entry {
	t.Helper()
	auth := envelope.AuthoritySameSigner
	header := envelope.ControlHeader{
		Destination:   "did:web:state:tn:davidson",
		SignerDID:     clerkDID,
		AuthorityPath: &auth,
	}
	entry, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	return entry
}

// appearanceDisplay renders the EIP-712 typed-data the wallet
// shows to every signer (Clerk + Attorney). Same fields, same
// digest.
func appearanceDisplay(attorneyDID, bpr string) *identity.TypedDataDisplay {
	return &identity.TypedDataDisplay{
		Domain: identity.EIP712Domain{
			Name:    "Judicial Network",
			Version: "v1",
			Salt:    "did:web:state:tn:davidson",
		},
		PrimaryType: "CounselAppearance",
		Fields: []identity.EIP712Field{
			{Name: "event_type", Type: "string", Value: "counsel_appearance"},
			{Name: "filed_by_did", Type: "string", Value: attorneyDID},
			{Name: "bpr_number", Type: "string", Value: bpr},
		},
	}
}

// fixtureWithTwoClerks layers a resolver that binds two clerk
// DIDs (intake clerk = primary signer; cosigning clerk = the
// court_clerk cosigner the rule requires). Models the real flow:
// one clerk receives the filing at the counter, a second clerk
// (or the same clerk's witness key) cosigns the on-log entry.
func fixtureWithTwoClerks(t *testing.T, clerk1DID, clerk2DID string) (*contractFixture, verification.RoleResolver) {
	t.Helper()
	f := newFixture(t)
	r := verification.NewMapRoleResolver().
		Bind(clerk1DID, "court_clerk", f.institutionalDID).
		Bind(clerk2DID, "court_clerk", f.institutionalDID)
	return f, r
}

// ─── happy path: defense counsel files appearance ─────────────────

func TestCounselAppearance_DefenseCounsel_Verified(t *testing.T) {
	clerkDID := "did:key:zQ3shCLERK"
	clerkCosignDID := "did:key:zQ3shCLERK2"
	atyDID := "did:key:zQ3shDEFENSE_E2E"

	f, res := fixtureWithTwoClerks(t, clerkDID, clerkCosignDID)
	f.provisionKey(t, clerkDID)
	f.provisionKey(t, clerkCosignDID)
	bindKey(t, f.identity, atyDID)

	entry := counselAppearanceEnvelope(t, clerkDID,
		counselAppearancePayload(atyDID, "TN-12345",
			schemas.FilerRoleDefenseCounsel, []string{"d-001"}))

	pos, err := delegation.SignAndSubmitCosigned(context.Background(),
		f.buildCtx, entry,
		appearanceDisplay(atyDID, "TN-12345"),
		"Filing counsel_appearance",
		[]string{atyDID, clerkCosignDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}

	got := f.envelopeAt(t, pos)
	v := verification.CheckCosignature(got, trial.MustCosignaturePolicy(),
		res, f.institutionalDID)
	if !v.OK {
		t.Fatalf("verifier rejected counsel_appearance: %s (%s)",
			v.Rejection, v.Reason)
	}
	if v.EventType != "counsel_appearance" {
		t.Errorf("event_type drift: %q", v.EventType)
	}
	if v.Capacity == nil || v.Capacity.DID != atyDID {
		t.Errorf("capacity drift: %+v", v.Capacity)
	}
}

// ─── happy path: civil attorney files appearance ──────────────────

func TestCounselAppearance_CivilAttorney_Verified(t *testing.T) {
	clerkDID := "did:key:zQ3shCLERK"
	clerkCosignDID := "did:key:zQ3shCLERK2"
	atyDID := "did:key:zQ3shCIVIL_E2E"

	f, res := fixtureWithTwoClerks(t, clerkDID, clerkCosignDID)
	f.provisionKey(t, clerkDID)
	f.provisionKey(t, clerkCosignDID)
	bindKey(t, f.identity, atyDID)

	entry := counselAppearanceEnvelope(t, clerkDID,
		counselAppearancePayload(atyDID, "TN-99999",
			schemas.FilerRoleCivilAttorney, []string{"p-001"}))

	pos, err := delegation.SignAndSubmitCosigned(context.Background(),
		f.buildCtx, entry,
		appearanceDisplay(atyDID, "TN-99999"),
		"Filing civil counsel_appearance",
		[]string{atyDID, clerkCosignDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}
	got := f.envelopeAt(t, pos)
	v := verification.CheckCosignature(got, trial.MustCosignaturePolicy(),
		res, f.institutionalDID)
	if !v.OK {
		t.Fatalf("verifier rejected civil counsel_appearance: %s (%s)",
			v.Rejection, v.Reason)
	}
}

// ─── reject: fiduciary cannot file counsel_appearance ─────────────

func TestCounselAppearance_FiduciaryRejected(t *testing.T) {
	clerkDID := "did:key:zQ3shCLERK"
	clerkCosignDID := "did:key:zQ3shCLERK2"
	fidDID := "did:key:zQ3shFIDUCIARY_E2E"

	f, res := fixtureWithTwoClerks(t, clerkDID, clerkCosignDID)
	f.provisionKey(t, clerkDID)
	f.provisionKey(t, clerkCosignDID)
	bindKey(t, f.identity, fidDID)

	entry := counselAppearanceEnvelope(t, clerkDID,
		counselAppearancePayload(fidDID, "TN-FIDUCIARY",
			schemas.FilerRoleFiduciary, []string{"d-001"}))

	pos, err := delegation.SignAndSubmitCosigned(context.Background(),
		f.buildCtx, entry,
		appearanceDisplay(fidDID, "TN-FIDUCIARY"),
		"Fiduciary attempts appearance",
		[]string{fidDID, clerkCosignDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}
	got := f.envelopeAt(t, pos)
	v := verification.CheckCosignature(got, trial.MustCosignaturePolicy(),
		res, f.institutionalDID)
	if v.OK {
		t.Error("fiduciary must NOT be permitted to file counsel_appearance")
	}
}

// ─── reject: missing bpr_number ───────────────────────────────────

func TestCounselAppearance_MissingBPR_Rejected(t *testing.T) {
	clerkDID := "did:key:zQ3shCLERK"
	clerkCosignDID := "did:key:zQ3shCLERK2"
	atyDID := "did:key:zQ3shATTORNEY_NOBPR"

	f, res := fixtureWithTwoClerks(t, clerkDID, clerkCosignDID)
	f.provisionKey(t, clerkDID)
	f.provisionKey(t, clerkCosignDID)
	bindKey(t, f.identity, atyDID)

	// Empty bpr_number → verifier rejects on RequiredCredentials.
	entry := counselAppearanceEnvelope(t, clerkDID,
		counselAppearancePayload(atyDID, "",
			schemas.FilerRoleDefenseCounsel, []string{"d-001"}))

	pos, err := delegation.SignAndSubmitCosigned(context.Background(),
		f.buildCtx, entry,
		appearanceDisplay(atyDID, ""),
		"counsel_appearance without bpr_number",
		[]string{atyDID, clerkCosignDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}
	got := f.envelopeAt(t, pos)
	v := verification.CheckCosignature(got, trial.MustCosignaturePolicy(),
		res, f.institutionalDID)
	if v.OK {
		t.Error("counsel_appearance without bpr_number must be rejected")
	}
}
