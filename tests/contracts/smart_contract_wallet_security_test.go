/*
FILE PATH:

	tests/contracts/smart_contract_wallet_security_test.go

DESCRIPTION:

	Security-property and SDK-seam pinning for v0.8.0 EIP-1271
	integration. Companion of smart_contract_wallet_test.go
	(verification semantics).

SECURITY PROPERTIES PINNED:
  - Cross-exchange replay defense: an entry whose Header.Destination
    differs from the registry's bound destination is rejected with
    ErrDestinationMismatch BEFORE any eth_call is issued. (No
    network roundtrip on a mismatched-destination probe.)
  - SigAlgoEIP1271 == 0x0006 on the wire and is accepted by
    ValidateAlgorithmID. Drift in either breaks every existing
    smart-contract-wallet entry.
  - The calldata the JN test computes is byte-for-byte the SAME
    calldata the SDK internally calls EthCall with — so the test
    stub bindings test the actual signature-acceptance semantics,
    not a parallel JN encoder that drifted from the SDK.
  - Compile-time pin of the v0.8.0 SDK surface JN depends on. A
    rename or deletion in the SDK breaks the JN build BEFORE
    runtime tests fire.
*/
package contracts

import (
	"errors"
	"strings"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/did"
)

// ─── cross-exchange replay defense (registry-level) ────────────

func TestSCW_DestinationMismatchRejectsBeforeRPC(t *testing.T) {
	// Build entry bound to a DIFFERENT destination, then verify
	// against a registry bound to scwDestination. The registry
	// MUST reject before issuing any eth_call.
	rpc := signatures.NewStubEthereumRPC()
	addr := scwSampleAddr()
	contractSig := []byte("x")

	entry, _, _ := scwBuildEntryFromContract(t, addr, "did:web:state:tn:knox", contractSig)
	// (no calldata binding — if the registry calls EthCall we
	// want it to surface a clear "no binding" error so the test
	// notices the leak.)

	registry := did.DefaultVerifierRegistryWithRPC(scwDestination, panicResolver{}, rpc)
	err := registry.VerifyEntry(ctx, entry)
	if !errors.Is(err, did.ErrDestinationMismatch) {
		t.Fatalf("cross-destination entry MUST reject with ErrDestinationMismatch; got %v", err)
	}
	if got := rpc.CallCount("eth_call"); got != 0 {
		t.Errorf("destination mismatch MUST NOT trigger any eth_call; got %d", got)
	}
}

// ─── pin-the-pinning: SigAlgoEIP1271 = 0x0006 on the wire ──────

func TestSCW_AlgoIDIsRegistered(t *testing.T) {
	if envelope.SigAlgoEIP1271 != 0x0006 {
		t.Errorf("SigAlgoEIP1271 wire value drift: want 0x0006, got 0x%04x — every smart-contract-wallet entry on the log breaks",
			envelope.SigAlgoEIP1271)
	}
	if err := envelope.ValidateAlgorithmID(envelope.SigAlgoEIP1271); err != nil {
		t.Errorf("SigAlgoEIP1271 must be accepted by ValidateAlgorithmID: %v", err)
	}
}

// ─── ABI calldata pinning at the JN seam ───────────────────────

// TestSCW_CalldataMatchesSDKEncoding pins that the calldata the JN
// test computes is byte-for-byte the SAME calldata the SDK
// internally calls EthCall with. Drift here would mean the test
// stub binding misses and we'd see misleading "no binding" errors
// instead of the magic-value semantics we're actually validating.
func TestSCW_CalldataMatchesSDKEncoding(t *testing.T) {
	rpc := signatures.NewStubEthereumRPC()
	addr := scwSampleAddr()
	contractSig := []byte("test-binding-key")

	entry, hash, calldata := scwBuildEntryFromContract(t, addr, scwDestination, contractSig)

	// Recompute what the SDK encodes; assert byte-equality.
	want := signatures.EncodeIsValidSignatureCalldata(hash, contractSig)
	if !bytesEqual(calldata, want) {
		t.Fatalf("calldata drift between JN test and SDK encoder")
	}

	// Cross-check by binding a wrong calldata and asserting the
	// real verification path misses (magic-binding vs calldata-
	// binding distinction).
	wrongCalldata := append([]byte{}, calldata...)
	wrongCalldata[len(wrongCalldata)-1] ^= 0xFF
	rpc.BindEthCall(addr, wrongCalldata, scwMagicReturn())

	registry := did.DefaultVerifierRegistryWithRPC(scwDestination, panicResolver{}, rpc)
	err := registry.VerifyEntry(ctx, entry)
	if err == nil {
		t.Fatal("calldata mismatch MUST cause stub to miss binding")
	}
	if errors.Is(err, signatures.ErrEIP1271InvalidMagic) {
		t.Errorf("test bug: JN's calldata accidentally matched the wrong binding")
	}
	if !strings.Contains(err.Error(), "no binding") {
		t.Errorf("expected 'no binding' from stub when calldata mismatches; got %v", err)
	}
}

// ─── compile-time pins for the v0.8.0 SDK seam ─────────────────
//
// A rename or removal of any of these in the SDK breaks the JN
// build BEFORE any runtime test runs.
var (
	_                              = signatures.VerifyEIP1271
	_                              = signatures.EncodeIsValidSignatureCalldata
	_                              = signatures.NewStubEthereumRPC
	_                              = signatures.ErrEIP1271InvalidMagic
	_                              = signatures.ErrEIP1271ContractEmpty
	_                              = signatures.ErrEthCallReverted
	_                              = did.DefaultVerifierRegistryWithRPC
	_                              = did.NewPKHVerifierWithRPC
	_                              = envelope.SigAlgoEIP1271
	_ signatures.EthereumRPCClient = (*signatures.StubEthereumRPC)(nil)
)

// ─── byte-equality helper ──────────────────────────────────────

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
