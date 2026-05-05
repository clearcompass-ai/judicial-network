/*
FILE PATH: tests/contracts/delegation_cosigned_filing_test.go

DESCRIPTION:

	End-to-end contract tests for the inline two-actor signing
	pipeline, reworked per the v1.4 design decision:
	NO attorney registry. The on-log payload IS the credentials
	claim. The cosigner DID IS the attestation.

	Filing model the dictionary describes:
	  - The Clerk (ActorSigner) is Header.SignerDID and Signatures[0].
	    In the v1.4 dictionary's words: "every motion or brief is
	    manually hashed and signed to the ledger by a Clerk."
	  - The attorney (ActorFiler) holds their OWN DID (e.g., a
	    Privy embedded wallet). They cosign — Signatures[1].
	  - The payload carries a `filed_by_capacity` block that
	    declares the attorney's role and credentials (BPR number,
	    jurisdiction, firm). The cosigner DID matches
	    filed_by_capacity.did, so the attestation is bound to the
	    identity making the credential claim.
	  - No off-log registry is consulted. The aggregator
	    surfaces the capacity claim verbatim from the log.

	Pins:
	  - 2-signature envelope round-trips through envelope.Deserialize.
	  - Signatures[0] = Clerk (== Header.SignerDID).
	  - Signatures[1] = Attorney (== payload.filed_by_capacity.did).
	  - payload.filed_by_capacity preserves role + credentials.
	  - 1-of-N cosigner rejection blocks submission entirely.
	  - SigningPayload digest stable across sign-and-serialize.
*/
package contracts

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/judicial-network/api/exchange/identity"
	"github.com/clearcompass-ai/judicial-network/delegation"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ─── helpers ────────────────────────────────────────────────────────

// filingDisplay renders the EIP-712 typed-data the wallet shows to
// every signer (Clerk + Attorney). Both see the same fields and
// sign the same digest.
func filingDisplay(filerDID, bprNumber string) *identity.TypedDataDisplay {
	return &identity.TypedDataDisplay{
		Domain: identity.EIP712Domain{
			Name:    "Judicial Network",
			Version: "v1",
			Salt:    "did:web:state:tn:davidson",
		},
		PrimaryType: "AttorneyFiling",
		Fields: []identity.EIP712Field{
			{Name: "event_type", Type: "string", Value: "motion_continuance"},
			{Name: "filed_by_did", Type: "string", Value: filerDID},
			{Name: "bpr_number", Type: "string", Value: bprNumber},
		},
	}
}

// buildFilingEntry constructs the unsigned envelope. SignerDID is
// the Clerk; the payload carries the filed_by_capacity block that
// self-describes the attorney filing on their own behalf.
func buildFilingEntry(t *testing.T, clerkDID, attorneyDID, bprNumber string) *envelope.Entry {
	t.Helper()
	auth := envelope.AuthoritySameSigner
	header := envelope.ControlHeader{
		Destination:   "did:web:state:tn:davidson",
		SignerDID:     clerkDID,
		AuthorityPath: &auth,
	}
	payload, _ := json.Marshal(map[string]any{
		"event_type":   "motion_continuance",
		"case_ref":     "2027-CV-1234",
		"custom_title": "Motion to Reschedule Hearing",
		"filed_by_capacity": map[string]any{
			"actor": 2, // ActorFiler
			"role":  "defense_counsel",
			"did":   attorneyDID,
			"credentials": map[string]any{
				"bpr_number":   bprNumber,
				"jurisdiction": "TN",
				"firm":         "Smith & Jones LLP",
			},
			"sworn_at": "2027-04-01T10:30:00Z",
		},
	})
	entry, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	return entry
}

// bindKey provisions a fresh secp256k1 key on the StubProvider for
// the given DID. Used for both Tier 1 and Tier 2 actors — Privy
// gives both classes wallets; what makes a key a "network key" is
// the on-log delegation chain, not the existence of the keypair.
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

	// Tier 1 Clerk: bound to the contract fixture's IdentityProvider
	// because they're a network keyholder with a delegation entry.
	clerkDID := f.provisionKey(t, "did:key:zQ3shCLERK")

	// Tier 2 Attorney: also bound to the StubProvider because every
	// signer needs SignDigest. The attorney has NO delegation entry
	// and is NOT in the role catalog — only a wallet.
	attorneyDID := "did:key:zQ3shATTORNEY"
	bindKey(t, f.identity, attorneyDID)

	const bprNumber = "TN-12345"
	entry := buildFilingEntry(t, clerkDID, attorneyDID, bprNumber)

	pos, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, entry,
		filingDisplay(attorneyDID, bprNumber),
		"Filing motion_continuance for "+attorneyDID,
		[]string{attorneyDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}
	if pos.Sequence != 1 {
		t.Errorf("position seq drift: %d", pos.Sequence)
	}

	// Round-trip through envelope.Deserialize.
	got := f.envelopeAt(t, pos)
	if got.Header.SignerDID != clerkDID {
		t.Errorf("primary: got %q want %q", got.Header.SignerDID, clerkDID)
	}
	if len(got.Signatures) != 2 {
		t.Fatalf("Signatures: got %d, want 2 (Clerk + Attorney)", len(got.Signatures))
	}
	if got.Signatures[0].SignerDID != clerkDID {
		t.Errorf("Signatures[0]: %q != Clerk %q", got.Signatures[0].SignerDID, clerkDID)
	}
	if got.Signatures[1].SignerDID != attorneyDID {
		t.Errorf("Signatures[1]: %q != Attorney %q", got.Signatures[1].SignerDID, attorneyDID)
	}
	for i, s := range got.Signatures {
		if s.AlgoID != envelope.SigAlgoECDSA {
			t.Errorf("Signatures[%d] alg: %d", i, s.AlgoID)
		}
		if len(s.Bytes) != 64 {
			t.Errorf("Signatures[%d] bytes: %d (want 64)", i, len(s.Bytes))
		}
	}

	// Payload preserves filed_by_capacity exactly; 
	// aggregator reads the whole block verbatim.
	var payload map[string]any
	if err := json.Unmarshal(got.DomainPayload, &payload); err != nil {
		t.Fatalf("payload parse: %v", err)
	}
	cap, ok := payload["filed_by_capacity"].(map[string]any)
	if !ok {
		t.Fatalf("filed_by_capacity missing or wrong type: %T", payload["filed_by_capacity"])
	}
	// The capacity claim must point at the Attorney's signing DID.
	// This is the integrity check that ties the credentials claim
	// to the cryptographic attestation.
	if cap["did"] != attorneyDID {
		t.Errorf("capacity.did drift: got %v, want %s", cap["did"], attorneyDID)
	}
	if cap["actor"] != float64(2) {
		t.Errorf("capacity.actor: got %v, want 2 (ActorFiler)", cap["actor"])
	}
	if cap["role"] != "defense_counsel" {
		t.Errorf("capacity.role drift: %v", cap["role"])
	}
	creds, _ := cap["credentials"].(map[string]any)
	if creds["bpr_number"] != bprNumber {
		t.Errorf("capacity.credentials.bpr_number drift: %v", creds["bpr_number"])
	}
}

// TestCosignedFiling_CapacityDIDMatchesCosigner pins the design
// invariant the  verifier will enforce: the DID claimed in
// payload.filed_by_capacity.did MUST appear in entry.Signatures.
// Without this, an attorney could be impersonated — anyone could
// claim "this filing is by Jane Smith Esq." in the payload.
func TestCosignedFiling_CapacityDIDMatchesCosigner(t *testing.T) {
	f := newFixture(t)
	clerkDID := f.provisionKey(t, "did:key:zQ3shCLERK")
	attorneyDID := "did:key:zQ3shATTORNEY"
	bindKey(t, f.identity, attorneyDID)

	entry := buildFilingEntry(t, clerkDID, attorneyDID, "TN-12345")
	pos, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, entry,
		filingDisplay(attorneyDID, "TN-12345"), "filing", []string{attorneyDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}

	got := f.envelopeAt(t, pos)
	var payload map[string]any
	json.Unmarshal(got.DomainPayload, &payload)
	cap, _ := payload["filed_by_capacity"].(map[string]any)
	claimedDID, _ := cap["did"].(string)

	// Walk Signatures looking for the claimed DID. (This is the
	// shape the  verifier will codify.)
	found := false
	for _, s := range got.Signatures {
		if s.SignerDID == claimedDID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("filed_by_capacity.did=%q not present in any Signatures.SignerDID; capacity claim is unsigned",
			claimedDID)
	}
}

// TestCosignedFiling_RejectionBlocksSubmission pins that if any
// signer (Clerk OR Attorney) declines, the ledger never sees the
// entry — the wallet's reject is end-to-end.
func TestCosignedFiling_RejectionBlocksSubmission(t *testing.T) {
	f := newFixture(t)
	clerkDID := f.provisionKey(t, "did:key:zQ3shCLERK")
	attorneyDID := "did:key:zQ3shATTORNEY"
	bindKey(t, f.identity, attorneyDID)

	// The attorney declines to cosign their own filing.
	f.identity.RejectSigning(attorneyDID, true)

	entry := buildFilingEntry(t, clerkDID, attorneyDID, "TN-12345")
	_, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, entry,
		filingDisplay(attorneyDID, "TN-12345"), "Filing", []string{attorneyDID})
	if err == nil {
		t.Fatal("expected error on cosigner rejection")
	}
	if !errors.Is(err, delegation.ErrSignFailed) {
		t.Errorf("expected ErrSignFailed, got: %v", err)
	}
	if !errors.Is(err, identity.ErrSignRejected) {
		t.Errorf("error must wrap identity.ErrSignRejected: %v", err)
	}
	if got := len(f.ledger.bySeq); got != 0 {
		t.Errorf("ledger must not have any entries; got %d", got)
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
	attorneyDID := "did:key:zQ3shATTORNEY"
	bindKey(t, f.identity, attorneyDID)

	preEntry := buildFilingEntry(t, clerkDID, attorneyDID, "TN-1")
	preDigest := envelope.SigningPayload(preEntry)

	pos, err := delegation.SignAndSubmitCosigned(context.Background(), f.buildCtx, preEntry,
		filingDisplay(attorneyDID, "TN-1"), "test", []string{attorneyDID})
	if err != nil {
		t.Fatalf("SignAndSubmitCosigned: %v", err)
	}

	got := f.envelopeAt(t, pos)
	postDigest := envelope.SigningPayload(got)
	if string(preDigest) != string(postDigest) {
		t.Error("SigningPayload changed across sign-and-serialize round trip; cosigners would mismatch verifier's digest")
	}
}

// TestCosignedFiling_BindKeyHelper is a sanity check that bindKey
// returns a usable pubkey object — keeps the helper from being
// flagged as dead code.
func TestCosignedFiling_BindKeyHelper(t *testing.T) {
	sp := identity.NewStubProvider()
	pub := bindKey(t, sp, "did:key:zQ3shA")
	if pub == nil {
		t.Fatal("bindKey returned nil pubkey")
	}
}
