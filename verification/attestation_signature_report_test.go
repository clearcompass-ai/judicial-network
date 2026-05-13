/*
FILE PATH: verification/attestation_signature_report_test.go

DESCRIPTION:

	Tests for the JN attestation.VerifyEntrySignatures adapter.

	Coverage:
	  - Nil entry / nil verifier surface ErrSignatureReport.
	  - Happy path with a single valid signature returns a report
	    with Total=1 and ValidCount=1; AllSignaturesValid is true.
	  - When the verifier returns an error, the per-signature Err
	    is populated and FirstInvalidSigner names the failing DID.
	  - AllSignaturesValid handles nil report.
	  - FirstInvalidSigner handles nil report.
*/
package verification

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
)

// buildSingleSignerEntry builds a fully-signed single-signature
// entry suitable for VerifyEntrySignatures.
func buildSingleSignerEntry(t *testing.T, signerDID string) *envelope.Entry {
	t.Helper()
	auth := envelope.AuthoritySameSigner
	unsigned, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     signerDID,
		Destination:   "did:web:dst",
		AuthorityPath: &auth,
	}, []byte(`{"ok":true}`))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	hash := sha256.Sum256(envelope.SigningPayload(unsigned))
	sigBytes, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	signed, err := envelope.NewEntry(unsigned.Header, unsigned.DomainPayload, []envelope.Signature{
		{SignerDID: signerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sigBytes},
	})
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	return signed
}

// ─── Input guards ───────────────────────────────────────────────

func TestVerifyEntrySignatureReport_NilEntry(t *testing.T) {
	_, err := VerifyEntrySignatureReport(context.Background(), nil, acceptAllSigVerifier{})
	if !errors.Is(err, ErrSignatureReport) {
		t.Errorf("err = %v, want errors.Is(ErrSignatureReport)", err)
	}
}

func TestVerifyEntrySignatureReport_NilVerifier(t *testing.T) {
	entry := buildSingleSignerEntry(t, "did:key:zA")
	_, err := VerifyEntrySignatureReport(context.Background(), entry, nil)
	if !errors.Is(err, ErrSignatureReport) {
		t.Errorf("err = %v, want errors.Is(ErrSignatureReport)", err)
	}
}

// ─── Happy path ───────────────────────────────────────────────────

func TestVerifyEntrySignatureReport_HappyPath(t *testing.T) {
	entry := buildSingleSignerEntry(t, "did:key:zA")
	report, err := VerifyEntrySignatureReport(context.Background(), entry, acceptAllSigVerifier{})
	if err != nil {
		t.Fatalf("VerifyEntrySignatureReport: %v", err)
	}
	if report.Total != 1 {
		t.Errorf("Total = %d, want 1", report.Total)
	}
	if report.ValidCount != 1 {
		t.Errorf("ValidCount = %d, want 1", report.ValidCount)
	}
	if !AllSignaturesValid(report) {
		t.Errorf("AllSignaturesValid = false on a fully-valid report")
	}
	if got := FirstInvalidSigner(report); got != "" {
		t.Errorf("FirstInvalidSigner = %q, want \"\"", got)
	}
}

// ─── Per-signature failure ──────────────────────────────────

func TestVerifyEntrySignatureReport_FailedVerifier_PopulatesPerSigErr(t *testing.T) {
	entry := buildSingleSignerEntry(t, "did:key:zBad")
	report, err := VerifyEntrySignatureReport(context.Background(), entry, rejectAllSigVerifier{})
	if err != nil {
		t.Fatalf("VerifyEntrySignatureReport returned envelope-level err: %v", err)
	}
	if report.ValidCount != 0 {
		t.Errorf("ValidCount = %d, want 0", report.ValidCount)
	}
	if AllSignaturesValid(report) {
		t.Errorf("AllSignaturesValid = true on a failed report")
	}
	if got := FirstInvalidSigner(report); got != "did:key:zBad" {
		t.Errorf("FirstInvalidSigner = %q, want did:key:zBad", got)
	}
}

// ─── Helpers on nil report ──────────────────────────────────

func TestAllSignaturesValid_NilReport(t *testing.T) {
	if AllSignaturesValid(nil) {
		t.Errorf("nil report MUST return false")
	}
}

func TestFirstInvalidSigner_NilReport(t *testing.T) {
	if got := FirstInvalidSigner(nil); got != "" {
		t.Errorf("nil report MUST return empty string; got %q", got)
	}
}
