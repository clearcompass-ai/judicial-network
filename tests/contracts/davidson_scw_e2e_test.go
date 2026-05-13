/*
FILE PATH: tests/contracts/davidson_scw_e2e_test.go

DESCRIPTION:

	Davidson County smart-contract-wallet end-to-end test. Pins the
	production-validation contract for an SCW-identified caller
	driving the daily-clerk flow against the **composed JN listener**
	(api.NewServer):

	  1. Composer up; Davidson Bundle registered.
	  2. SCW caller (did:pkh:eip155:1:0x<scw-addr>) invokes
	     POST /v1/judicial/cases — composer routes to the judicial
	     handler which returns a BuildResponse carrying the unsigned
	     entry's signing payload.
	  3. Caller hashes signing_payload (SHA-256), signs with the
	     controlling EOA via the  signer.Adapter (output
	     is 65-byte Ethereum-format r||s||v).
	  4. Caller wraps via signatures.PackMinimalSCWSignature → the
	     opaque contract-signature bytes for MinimalSCW.isValidSignature.
	  5. Caller rebuilds the unsigned entry locally (drift detector:
	     the API's signing_payload MUST equal what envelope.SigningPayload
	     produces from the same inputs).
	  6. Caller attaches an EIP-1271 envelope.Signature, validates
	     the entry, and runs it through did.DefaultVerifierRegistryWithRPC
	     with a stubbed eth_call binding to the canonical magic value
	     — the verifier registry MUST accept.

	Negative paths pinned in this file:
	  - Wrong eth_call return → ErrEIP1271InvalidMagic.
	  - Empty caller DID → 401.

	Harness, helpers, and the rebuilder live in
	davidson_scw_e2e_setup_test.go.
*/
package contracts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/did"

	"github.com/clearcompass-ai/judicial-network/api/judicial"
)

// ─────────────────────────────────────────────────────────────────────
// Happy path
// ─────────────────────────────────────────────────────────────────────

func TestDavidsonSCW_E2E_HappyPath(t *testing.T) {
	ctx := context.Background()
	h := newSCWE2EHarness(t)

	// 1. Drive POST /v1/judicial/cases as the SCW caller.
	body := []byte(`{
		"destination":   "` + scwE2EDestination + `",
		"docket_number": "` + scwE2EDocket + `",
		"case_type":     "criminal",
		"filed_date":    "2026-01-15",
		"event_time":    1758000000000000
	}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases", bytes.NewReader(body))
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /v1/judicial/cases: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 2. Decode BuildResponse.
	var resp struct {
		SigningPayload string                 `json:"signing_payload"`
		EntryBytes     string                 `json:"entry_bytes"`
		Header         envelope.ControlHeader `json:"header"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode BuildResponse: %v", err)
	}
	signingPayload, err := base64.StdEncoding.DecodeString(resp.SigningPayload)
	if err != nil {
		t.Fatalf("decode signing_payload: %v", err)
	}

	// 3. Drift detector — independent rebuild MUST match the API's
	// signing_payload byte-for-byte.
	rebuilt := rebuildUnsignedEntry(t, h.scwDID, scwE2EDocket, 1758000000000000)
	if want := envelope.SigningPayload(rebuilt); !bytes.Equal(want, signingPayload) {
		t.Fatalf("API signing_payload diverges from independent rebuild\n  got %x\n want %x",
			signingPayload[:minInt(len(signingPayload), 64)],
			want[:minInt(len(want), 64)])
	}
	if resp.Header.SignerDID != h.scwDID {
		t.Errorf("Header.SignerDID = %q, want %q (composer MUST source from auth context)",
			resp.Header.SignerDID, h.scwDID)
	}
	if resp.Header.Destination != scwE2EDestination {
		t.Errorf("Header.Destination = %q, want %q",
			resp.Header.Destination, scwE2EDestination)
	}

	// 4. Hash signing_payload, sign with controlling EOA,
	// pack as MinimalSCW EIP-1271 contract-sig bytes.
	digest := sha256.Sum256(signingPayload)
	ownerSig, err := h.signer.Sign(digest)
	if err != nil {
		t.Fatalf("signer.Sign: %v", err)
	}
	contractSig, err := signatures.PackMinimalSCWSignature(ownerSig)
	if err != nil {
		t.Fatalf("PackMinimalSCWSignature: %v", err)
	}

	// 5. Attach the EIP-1271 signature to the rebuilt entry +
	// validate. (The rebuilt entry shares its SigningPayload with
	// the API response, so this signature is valid against either.)
	rebuilt.Signatures = append(rebuilt.Signatures, envelope.Signature{
		SignerDID: h.scwDID,
		AlgoID:    envelope.SigAlgoEIP1271,
		Bytes:     contractSig,
	})
	if err := rebuilt.Validate(); err != nil {
		t.Fatalf("entry.Validate: %v", err)
	}

	// 6. Run through the SDK verifier registry with a stub eth_call
	// bound to the canonical magic-value return — must accept.
	rpc := signatures.NewStubEthereumRPC()
	calldata := signatures.EncodeIsValidSignatureCalldata(digest, contractSig)
	rpc.BindEthCall(scwE2EAddr(), calldata, scwE2EMagicReturn())

	registry := did.DefaultVerifierRegistryWithRPC(scwE2EDestination, panicResolver{}, rpc)
	if err := registry.VerifyEntry(ctx, rebuilt); err != nil {
		t.Fatalf("verifier registry rejected JN-built EIP-1271 entry: %v", err)
	}
	if got := rpc.CallCount("eth_call"); got != 1 {
		t.Errorf("expected exactly 1 eth_call; got %d", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Negative — wrong magic-value return rejected
// ─────────────────────────────────────────────────────────────────────

func TestDavidsonSCW_E2E_RejectsBadMagic(t *testing.T) {
	ctx := context.Background()
	h := newSCWE2EHarness(t)

	body := []byte(`{
		"destination":   "` + scwE2EDestination + `",
		"docket_number": "` + scwE2EDocket + `",
		"case_type":     "criminal",
		"filed_date":    "2026-01-15",
		"event_time":    1758000000000000
	}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases", bytes.NewReader(body))
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup POST: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		SigningPayload string `json:"signing_payload"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	signingPayload, _ := base64.StdEncoding.DecodeString(resp.SigningPayload)
	digest := sha256.Sum256(signingPayload)

	ownerSig, err := h.signer.Sign(digest)
	if err != nil {
		t.Fatalf("signer.Sign: %v", err)
	}
	contractSig, err := signatures.PackMinimalSCWSignature(ownerSig)
	if err != nil {
		t.Fatalf("PackMinimalSCWSignature: %v", err)
	}

	rebuilt := rebuildUnsignedEntry(t, h.scwDID, scwE2EDocket, 1758000000000000)
	rebuilt.Signatures = append(rebuilt.Signatures, envelope.Signature{
		SignerDID: h.scwDID, AlgoID: envelope.SigAlgoEIP1271, Bytes: contractSig,
	})
	if err := rebuilt.Validate(); err != nil {
		t.Fatalf("entry.Validate: %v", err)
	}

	// Stub eth_call returns all-zeros — verifier MUST reject with
	// ErrEIP1271InvalidMagic.
	rpc := signatures.NewStubEthereumRPC()
	calldata := signatures.EncodeIsValidSignatureCalldata(digest, contractSig)
	rpc.BindEthCall(scwE2EAddr(), calldata, make([]byte, 32))

	registry := did.DefaultVerifierRegistryWithRPC(scwE2EDestination, panicResolver{}, rpc)
	verr := registry.VerifyEntry(ctx, rebuilt)
	if !errors.Is(verr, signatures.ErrEIP1271InvalidMagic) {
		t.Fatalf("bad magic value MUST reject with ErrEIP1271InvalidMagic; got %v", verr)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 401 — caller resolver returns empty string
// ─────────────────────────────────────────────────────────────────────

func TestDavidsonSCW_E2E_NoCaller_401(t *testing.T) {
	h := newSCWE2EHarness(t)
	judicial.SetCallerDIDResolver(func(*http.Request) string { return "" })

	body := []byte(`{"destination":"` + scwE2EDestination + `",
		"docket_number":"x","case_type":"criminal","filed_date":"2026-01-15"}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/judicial/cases", bytes.NewReader(body))
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "unauthenticated") {
		t.Errorf("body = %q", rec.Body.String())
	}
}
