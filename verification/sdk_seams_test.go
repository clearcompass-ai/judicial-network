/*
FILE PATH: verification/sdk_seams_test.go

DESCRIPTION:

	Tests for the four SDK-delegation seams added in PR C:

	  - VerifyEvidenceChainViaSDK     (wraps verifier.VerifyEvidenceChain)
	  - VerifyEntryViaSDK             (wraps verifier.VerifyComplete)
	  - (*AuthorityResolver).VerifyKeyAtPosition (wraps verifier.VerifyKeyAtPosition)
	  - CheckCosignatureWithVerifier  (wraps attestation.VerifyEntrySignatures
	                                    + delegates to existing CheckCosignature)

	Each test pins the seam's contract: input-guard rejection paths
	return the typed JN sentinel; SDK sentinels remain reachable via
	errors.Is on the wrapped error. Per-stage / per-hop failures
	populate the report, NOT the top-level error.

	The seams are thin orchestrators; signature-math correctness lives
	in the SDK's own test surface. These tests pin the contract at the
	wrapper boundary.
*/
package verification

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// ─── VerifyEvidenceChainViaSDK ─────────────────────────────────

func TestVerifyEvidenceChainViaSDK_NilFetcher(t *testing.T) {
	_, err := VerifyEvidenceChainViaSDK(
		context.Background(),
		types.LogPosition{LogDID: "did:web:l", Sequence: 1},
		nil,
		verifier.WalkParams{},
	)
	if !errors.Is(err, ErrEvidenceChainSDK) {
		t.Errorf("err = %v, want errors.Is(ErrEvidenceChainSDK)", err)
	}
}

// ─── VerifyEntryViaSDK ─────────────────────────────────────────

func TestVerifyEntryViaSDK_NilEntry_WrapsSDKErr(t *testing.T) {
	_, err := VerifyEntryViaSDK(
		context.Background(),
		verifier.VerifyCompleteParams{
			Entry:             nil, // SDK rejects envelope-level
			SignatureVerifier: acceptAllSigVerifier{},
		},
	)
	if !errors.Is(err, ErrPathCSDK) {
		t.Errorf("err = %v, want errors.Is(ErrPathCSDK)", err)
	}
}

// ─── (*AuthorityResolver).VerifyKeyAtPosition ──────────────────

func TestAuthorityResolver_VerifyKeyAtPosition_WrapsSDKSentinel(t *testing.T) {
	r := &AuthorityResolver{}
	// Empty SignerDID → SDK returns ErrEmptySignerDID (or similar
	// guard); we just verify the JN wrapper wraps it.
	_, err := r.VerifyKeyAtPosition(
		context.Background(),
		verifier.KeyAtPositionQuery{}, // zero-value triggers SDK guard
		nil,
	)
	if !errors.Is(err, ErrKeyAtPositionSDK) {
		t.Errorf("err = %v, want errors.Is(ErrKeyAtPositionSDK)", err)
	}
}

// ─── CheckCosignatureWithVerifier ──────────────────────────────

// signedSingleSigEntry builds a fully-signed single-sig entry for
// the CheckCosignatureWithVerifier tests. Reuses the test-helper
// pattern from attestation_signature_report_test.go.
func signedSingleSigEntry(t *testing.T, signerDID, eventType string) *envelope.Entry {
	t.Helper()
	auth := envelope.AuthoritySameSigner
	payload := []byte(`{"event_type":"` + eventType + `"}`)
	unsigned, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     signerDID,
		Destination:   "did:web:dst",
		AuthorityPath: &auth,
	}, payload)
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

func TestCheckCosignatureWithVerifier_EnvelopeNilEntry_WrapsSDK(t *testing.T) {
	_, err := CheckCosignatureWithVerifier(
		context.Background(),
		nil, // nil entry → SDK ErrNilEntry
		nil,
		nil,
		"did:web:exA",
		acceptAllSigVerifier{},
	)
	if !errors.Is(err, ErrCosignatureCryptoSDK) {
		t.Errorf("err = %v, want errors.Is(ErrCosignatureCryptoSDK)", err)
	}
}

func TestCheckCosignatureWithVerifier_NilSigVerifier_WrapsSDK(t *testing.T) {
	entry := signedSingleSigEntry(t, "did:key:zSigner", "verdict")
	_, err := CheckCosignatureWithVerifier(
		context.Background(),
		entry,
		nil,
		nil,
		"did:web:exA",
		nil, // nil verifier → SDK ErrNilSignatureVerifier
	)
	if !errors.Is(err, ErrCosignatureCryptoSDK) {
		t.Errorf("err = %v, want errors.Is(ErrCosignatureCryptoSDK)", err)
	}
}

func TestCheckCosignatureWithVerifier_CryptoRejected_VerdictBranch(t *testing.T) {
	entry := signedSingleSigEntry(t, "did:key:zSigner", "verdict")
	// rejectAllSigVerifier fails every per-sig verification →
	// per-signature failure → CosigRejectCryptoInvalid verdict.
	v, err := CheckCosignatureWithVerifier(
		context.Background(),
		entry,
		nil, // pol not consulted on the crypto-reject path
		nil,
		"did:web:exA",
		rejectAllSigVerifier{},
	)
	if err != nil {
		t.Fatalf("got err = %v, want nil (crypto failure returns verdict, not envelope err)", err)
	}
	if v == nil {
		t.Fatal("got nil verdict; want non-nil with CosigRejectCryptoInvalid")
	}
	if v.OK {
		t.Errorf("verdict.OK = true on crypto-rejected entry")
	}
	if v.Rejection != CosigRejectCryptoInvalid {
		t.Errorf("Rejection = %q, want %q", v.Rejection, CosigRejectCryptoInvalid)
	}
}

// Compile-time pin — the seam symbols this test exercises.
var (
	_ = VerifyEvidenceChainViaSDK
	_ = VerifyEntryViaSDK
	_ = (*AuthorityResolver)(nil).VerifyKeyAtPosition
	_ = CheckCosignatureWithVerifier
)
