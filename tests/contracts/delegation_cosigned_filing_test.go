/*
FILE PATH: tests/contracts/delegation_cosigned_filing_test.go

DESCRIPTION:
    End-to-end contract tests for the inline two-actor signing
    pipeline (Phase 3B). Exercises the attorney-filing scenario the
    v1.3 Event Dictionary describes:

      - A Tier 2 attorney (registered in directory.AttorneyRegistry)
        cannot sign on their own.
      - A Clerk (Tier 1) builds the envelope with payload.filed_by =
        attorney.ID; the Clerk's DID goes in Header.SignerDID and
        Signatures[0].
      - A Tier 1 cosigner (typically an Adjudicator) cosigns; their
        DID lands at Signatures[1].
      - The operator receives a single envelope with two signatures
        over the same SigningPayload digest.

    Pins:
      - 2-signature envelope round-trips through envelope.Deserialize.
      - Signatures[0].SignerDID == Header.SignerDID == Clerk.
      - Signatures[1].SignerDID == cosigner DID.
      - payload.filed_by survives serialization.
      - 1-of-N cosigner rejection blocks submission entirely.
*/
package contracts

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/api/exchange/identity"
	"github.com/clearcompass-ai/judicial-network/delegation"
	"github.com/clearcompass-ai/judicial-network/directory"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ─── helpers ────────────────────────────────────────────────────────

func filingDisplay(filedBy string) *identity.TypedDataDisplay {
	return &identity.TypedDataDisplay{
		Domain: identity.EIP712Domain{
			Name:    "Judicial Network",
			Version: "v1",
			Salt:    "did:web:da:davidson-tn",
		},
		PrimaryType: "AttorneyFiling",
		Fields: []identity.EIP712Field{
			{Name: "filed_by", Type: "string", Value: filedBy},
			{Name: "event_type", Type: "string", Value: "motion_continuance"},
		},
	}
}

// buildFilingEntry constructs an unsigned envelope with payload
// carrying filed_by + event_type (the dictionary's discriminator).
// SignerDID = the Clerk acting on the attorney's behalf.
func buildFilingEntry(t *testing.T, signerDID, filedBy string) *envelope.Entry {
	t.Helper()
	auth := envelope.AuthoritySameSigner
	header := envelope.ControlHeader{
		Destination:   "did:web:da:davidson-tn",
		SignerDID:     signerDID,
		AuthorityPath: &auth,
	}
	payload, _ := json.Marshal(map[string]any{
		"event_type":  "motion_continuance",
		"filed_by":    filedBy,
		"case_ref":    "2027-CV-1234",
		"custom_title": "Motion to Reschedule Hearing",
	})
	entry, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	return entry
}

// bindKey provisions a fresh secp256k1 key on the StubProvider for
// the given DID. Returns the public key (used for verification).
func bindKey(t *testing.T, sp *identity.StubProvider, did string) *secp256k1.PublicKey {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	sp.BindKey(did, priv)
	return priv.PubKey()
}

// ─── happy path ─────────────────────────────────────────────────────

func TestCosignedFiling_AttorneyMotion_TwoSignatures(t *testing.T) {
	f := newFixture(t)

	// Tier 1 actors with bound keys.
	clerkDID := f.provisionKey(t, "did:key:zQ3shCLERK")
	judgeDID := f.provisionKey(t, "did:key:zQ3shJUDGE")

	// Tier 2 attorney registered in the directory.
	attorneys := directory.NewInMemoryAttorneys()
	if err := attorneys.Register(directory.Attorney{
		ID:        "bar:TN:12345",
		Alias:     "Jane Smith, Esq.",
		Type:      directory.AttorneyTypeDefenseCounsel,
		BarNumber: "TN-12345",
	}); err != nil {
		t.Fatalf("attorney Register: %v", err)
	}

	att, _ := attorneys.Lookup("bar:TN:12345")
	if att.Status != directory.AttorneyActive {
		t.Fatalf("attorney must be active: %s", att.Status)
	}

	// Clerk builds the entry with attorney.ID in payload.filed_by.
	entry := buildFilingEntry(t, clerkDID, att.ID)

	pos, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, entry,
		filingDisplay(att.ID), "Filing motion_continuance for Jane Smith, Esq.",
		[]string{judgeDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}
	if pos.Sequence != 1 {
		t.Errorf("position seq drift: %d", pos.Sequence)
	}

	// Operator received exactly one envelope; deserialize.
	got := f.envelopeAt(t, pos)
	if got.Header.SignerDID != clerkDID {
		t.Errorf("primary: got %q want %q", got.Header.SignerDID, clerkDID)
	}
	if len(got.Signatures) != 2 {
		t.Fatalf("Signatures: got %d, want 2", len(got.Signatures))
	}
	if got.Signatures[0].SignerDID != clerkDID {
		t.Errorf("Signatures[0]: %q != clerk %q", got.Signatures[0].SignerDID, clerkDID)
	}
	if got.Signatures[1].SignerDID != judgeDID {
		t.Errorf("Signatures[1]: %q != judge %q", got.Signatures[1].SignerDID, judgeDID)
	}
	for i, s := range got.Signatures {
		if s.AlgoID != envelope.SigAlgoECDSA {
			t.Errorf("Signatures[%d] alg: %d", i, s.AlgoID)
		}
		if len(s.Bytes) != 64 {
			t.Errorf("Signatures[%d] bytes: %d (want 64)", i, len(s.Bytes))
		}
	}

	// Payload preserves filed_by — the aggregator's index column
	// (Phase 3E) reads this verbatim.
	var payload map[string]any
	if err := json.Unmarshal(got.DomainPayload, &payload); err != nil {
		t.Fatalf("payload parse: %v", err)
	}
	if payload["filed_by"] != "bar:TN:12345" {
		t.Errorf("filed_by drift: %v", payload["filed_by"])
	}
	if payload["event_type"] != "motion_continuance" {
		t.Errorf("event_type drift: %v", payload["event_type"])
	}
}

// TestCosignedFiling_RejectionBlocksSubmission pins that if any
// signer (primary OR cosigner) declines, the operator never sees
// the entry — the wallet's reject is end-to-end.
func TestCosignedFiling_RejectionBlocksSubmission(t *testing.T) {
	f := newFixture(t)
	clerkDID := f.provisionKey(t, "did:key:zQ3shCLERK")
	judgeDID := f.provisionKey(t, "did:key:zQ3shJUDGE")

	// Judge declines to cosign.
	f.identity.RejectSigning(judgeDID, true)

	entry := buildFilingEntry(t, clerkDID, "bar:TN:12345")
	_, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, entry,
		filingDisplay("bar:TN:12345"), "Filing", []string{judgeDID})
	if err == nil {
		t.Fatal("expected error on cosigner rejection")
	}
	if !errors.Is(err, delegation.ErrSignFailed) {
		t.Errorf("expected ErrSignFailed, got: %v", err)
	}
	if !errors.Is(err, identity.ErrSignRejected) {
		t.Errorf("error must wrap identity.ErrSignRejected: %v", err)
	}

	// Operator captured nothing.
	if got := len(f.operator.bySeq); got != 0 {
		t.Errorf("operator must not have any entries; got %d", got)
	}
}

// TestCosignedFiling_AttorneyDirectorySuspend pins that a suspended
// attorney's filings are still cryptographically valid (no sig
// math changes), but the directory's status is consultable so a
// future cosignature-mix policy (Phase 3C) can refuse to cosign
// for a suspended attorney. This test exercises the directory side
// of the boundary; the policy enforcement lives in 3C.
func TestCosignedFiling_AttorneySuspendedStatusVisible(t *testing.T) {
	attorneys := directory.NewInMemoryAttorneys()
	attorneys.Register(directory.Attorney{
		ID:        "bar:TN:99999",
		Alias:     "Suspended Counsel",
		Type:      directory.AttorneyTypeProsecutor,
		BarNumber: "TN-99999",
	})
	if err := attorneys.Suspend("bar:TN:99999", "ethics_inquiry"); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	got, _ := attorneys.Lookup("bar:TN:99999")
	if got.Status != directory.AttorneySuspended {
		t.Errorf("status: got %q, want suspended", got.Status)
	}
	if got.SuspensionReason != "ethics_inquiry" {
		t.Errorf("reason drift: %q", got.SuspensionReason)
	}
}

// TestCosignedFiling_DigestStableAcrossSigners pins the contract
// every cosigner depends on: the digest computed from
// SigningPayload(entry) before any signature is attached equals
// the digest the verifier recomputes from the deserialized entry.
// (The signatures section is excluded from SigningPayload.)
func TestCosignedFiling_DigestStableAcrossSigners(t *testing.T) {
	f := newFixture(t)
	clerkDID := f.provisionKey(t, "did:key:zQ3shCLERK")
	judgeDID := f.provisionKey(t, "did:key:zQ3shJUDGE")

	// Construct the same payload twice; both must produce the
	// same SigningPayload bytes pre-sign.
	preEntry := buildFilingEntry(t, clerkDID, "bar:TN:1")
	preDigest := envelope.SigningPayload(preEntry)

	pos, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, preEntry,
		filingDisplay("bar:TN:1"), "test", []string{judgeDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}

	got := f.envelopeAt(t, pos)
	postDigest := envelope.SigningPayload(got)
	if string(preDigest) != string(postDigest) {
		t.Error("SigningPayload changed across sign-and-serialize round trip; cosigners would mismatch verifier's digest")
	}
}

// TestCosignedFiling_AttorneyTimestamps pins that an Attorney
// record's CreatedAt is preserved across Suspend/Restore cycles —
// audit trails see the original onboarding date even as status
// fluctuates.
func TestCosignedFiling_AttorneyTimestamps(t *testing.T) {
	attorneys := directory.NewInMemoryAttorneys()
	attorneys.Register(directory.Attorney{
		ID:    "bar:TN:1",
		Alias: "X",
		Type:  directory.AttorneyTypeProsecutor,
	})
	original, _ := attorneys.Lookup("bar:TN:1")
	time.Sleep(time.Millisecond)
	attorneys.Suspend("bar:TN:1", "review")
	time.Sleep(time.Millisecond)
	attorneys.Restore("bar:TN:1")

	got, _ := attorneys.Lookup("bar:TN:1")
	if !got.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("CreatedAt mutated: was %v, now %v", original.CreatedAt, got.CreatedAt)
	}
	if !got.UpdatedAt.After(original.UpdatedAt) {
		t.Errorf("UpdatedAt did not advance through Suspend+Restore")
	}
}

// Sanity check that bindKey returns a usable pubkey object — keeps
// the helper from being unused.
func TestCosignedFiling_BindKeyHelper(t *testing.T) {
	sp := identity.NewStubProvider()
	pub := bindKey(t, sp, "did:key:zQ3shA")
	if pub == nil {
		t.Fatal("bindKey returned nil pubkey")
	}
}
