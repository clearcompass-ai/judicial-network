/*
FILE PATH:

	tests/contracts/smart_contract_wallet_security_test.go

DESCRIPTION:

	Security-property and SDK-seam pinning for v1.7.1 EIP-1271
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
  - The calldata the JN test computes for Multicall3.aggregate3 is
    byte-for-byte the SAME calldata the SDK internally calls
    EthCall with — so the test stub bindings test the actual
    signature-acceptance semantics, not a parallel JN encoder
    that drifted from the SDK.
  - Compile-time pin of the v1.7.1 SDK surface JN depends on. A
    rename or deletion in the SDK breaks the JN build BEFORE
    runtime tests fire.
  - K-of-N executor consensus (Trust Alignment 2): the SCW path
    requires QuorumK >= 2; pin the PKHVerifierOptions construction
    against the SDK's exported types.
*/
package contracts

import (
	"context"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/multicall3"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/did"
	sdktypes "github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/internal/testutil"
)

// ─── cross-exchange replay defense (registry-level) ────────────

func TestSCW_DestinationMismatchRejectsBeforeRPC(t *testing.T) {
	ctx := context.Background()
	// Build entry bound to a DIFFERENT destination, then verify
	// against a registry bound to scwDestination. The registry
	// MUST reject before issuing any eth_call.
	addr := scwSampleAddr()
	contractSig := []byte("x")

	entry, _, _ := scwBuildEntryFromContract(t, addr, "did:web:state:tn:knox", contractSig)
	// (no calldata binding — if the registry calls EthCall we
	// want it to surface a clear "no binding" error so the test
	// notices the leak.)

	registry, rpc1, rpc2 := scwQuorumRegistry(t, scwDestination, panicResolver{})
	err := registry.VerifyEntry(ctx, entry)
	if !errors.Is(err, did.ErrDestinationMismatch) {
		t.Fatalf("cross-destination entry MUST reject with ErrDestinationMismatch; got %v", err)
	}
	if got := rpc1.CallCount("eth_call"); got != 0 {
		t.Errorf("destination mismatch MUST NOT trigger any eth_call on executor 1; got %d", got)
	}
	if got := rpc2.CallCount("eth_call"); got != 0 {
		t.Errorf("destination mismatch MUST NOT trigger any eth_call on executor 2; got %d", got)
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

// ─── ABI calldata pinning at the JN seam ─────────────────────

// TestSCW_AggregateCalldataMatchesSDKEncoding pins that the
// Multicall3-wrapped calldata the JN test computes is byte-for-byte
// the SAME calldata the SDK internally calls EthCall with. Drift
// here would mean the test stub binding misses and we'd see
// misleading "no binding" errors instead of the magic-value
// semantics we're actually validating.
func TestSCW_AggregateCalldataMatchesSDKEncoding(t *testing.T) {
	ctx := context.Background()
	addr := scwSampleAddr()
	contractSig := []byte("test-binding-key")

	entry, hash, _ := scwBuildEntryFromContract(t, addr, scwDestination, contractSig)

	// Recompute the aggregate3 calldata the SDK PKHVerifier emits;
	// the helper uses the SDK's BuildEIP1271Calls + PackAggregate3
	// directly, so a divergence here is a Multicall3 wire-format
	// drift, not a JN encoder bug.
	check := multicall3.EIP1271Check{Address: addr, Hash: hash, Signature: contractSig}
	wantCalldata := multicall3.PackAggregate3(multicall3.BuildEIP1271Calls([]multicall3.EIP1271Check{check}))
	gotCalldata := scwSingleCheckCalldata(addr, hash, contractSig)
	if !bytesEqual(gotCalldata, wantCalldata) {
		t.Fatalf("aggregate3 calldata drift between JN helper and SDK encoder")
	}

	// Cross-check by binding a wrong calldata to BOTH stubs and
	// asserting the real verification path misses (binding-key
	// vs computed-calldata distinction).
	registry, rpc1, rpc2 := scwQuorumRegistry(t, scwDestination, panicResolver{})
	multicallAddr := testutil.Multicall3Addr()
	wrongCalldata := append([]byte{}, gotCalldata...)
	wrongCalldata[len(wrongCalldata)-1] ^= 0xFF
	resp := testutil.EncodeAggregate3Response(true, scwMagicReturn())
	rpc1.BindEthCall(multicallAddr, wrongCalldata, resp)
	rpc2.BindEthCall(multicallAddr, wrongCalldata, resp)

	err := registry.VerifyEntry(ctx, entry)
	if err == nil {
		t.Fatal("calldata mismatch MUST cause stub to miss binding")
	}
	// The stubs were bound to wrongCalldata, so the verifier's
	// (correctly computed) calldata misses the binding on every
	// executor → no node returns a usable result → no K-of-N
	// consensus. (A drift where JN's calldata accidentally matched
	// the wrong binding would surface as a magic/invalid verdict
	// instead, NOT as ErrExecutorQuorumNotReached.)
	if !errors.Is(err, did.ErrExecutorQuorumNotReached) {
		t.Errorf("calldata mismatch MUST surface ErrExecutorQuorumNotReached (no node bound); got %v", err)
	}
	if errors.Is(err, did.ErrExecutorQuorumDisagreesOnInvalid) {
		t.Errorf("test bug: JN's calldata accidentally matched the wrong binding")
	}
}

// ─── per-signature receipt collection (v1.7.0 — native receipts) ──

// TestSCW_PerSignatureReceiptCollection pins that the SDK's
// SignatureVerifierWithReceipt path produces a populated
// Web3VerificationReceipt for every EIP-1271 signature in an
// entry, and that the receipt's ChainID + Block fields match the
// configured PKHVerifierOptions. Trust Alignment 9 — domain
// separation extends DOWN to the receipt, which carries the
// chain + block + executor quorum that produced the verdict.
func TestSCW_PerSignatureReceiptCollection(t *testing.T) {
	ctx := context.Background()
	addr := scwSampleAddr()
	contractSig := []byte("native-receipt-binding-key")

	entry, hash, _ := scwBuildEntryFromContract(t, addr, scwDestination, contractSig)

	registry, rpc1, rpc2 := scwQuorumRegistry(t, scwDestination, panicResolver{})
	calldata := scwSingleCheckCalldata(addr, hash, contractSig)
	scwBindAggregate3Response(rpc1, rpc2, calldata, scwMagicReturn())

	// attestation.VerifyEntrySignatures dispatches each signature
	// through registry.VerifyWithReceipt (since *did.VerifierRegistry
	// satisfies attestation.SignatureVerifierWithReceipt) and
	// gathers the per-signature receipts into SignatureReport.Web3Receipts.
	report, err := attestation.VerifyEntrySignatures(ctx, entry, registry)
	if err != nil {
		t.Fatalf("VerifyEntrySignatures: %v", err)
	}
	if report.ValidCount != 1 {
		t.Fatalf("ValidCount = %d, want 1", report.ValidCount)
	}
	if len(report.Web3Receipts) != 1 {
		t.Fatalf("Web3Receipts len = %d, want 1", len(report.Web3Receipts))
	}
	rcpt := report.Web3Receipts[0]
	if rcpt.IsZero() {
		t.Fatal("EIP-1271 verification MUST populate a non-zero Web3VerificationReceipt")
	}
	if rcpt.ChainID != scwTestChainID {
		t.Errorf("receipt.ChainID = %d, want %d", rcpt.ChainID, scwTestChainID)
	}
	if rcpt.BlockNumber != scwTestBlockNumber {
		t.Errorf("receipt.BlockNumber = %d, want %d", rcpt.BlockNumber, scwTestBlockNumber)
	}
	if rcpt.BlockHash != scwTestBlockHash {
		t.Errorf("receipt.BlockHash drift")
	}
	if rcpt.ContractAddr != addr {
		t.Errorf("receipt.ContractAddr drift")
	}
	// Both executors agreed (K=2 / N=2).
	if got := len(rcpt.ExecutorQuorum.Clients); got != 2 {
		t.Errorf("ExecutorQuorum.Clients len = %d, want 2", got)
	}
}

// ─── compile-time pins for the v1.7.1 SDK seam ─────────────────
//
// A rename or removal of any of these in the SDK breaks the JN
// build BEFORE any runtime test runs.
var (
	_ = signatures.VerifyEIP1271
	_ = signatures.EncodeIsValidSignatureCalldata
	_ = signatures.NewStubEthereumRPC
	_ = signatures.ErrEIP1271InvalidMagic
	_ = signatures.ErrEIP1271ContractEmpty
	_ = signatures.ErrEthCallReverted
	_ = did.DefaultVerifierRegistry
	_ = did.NewPKHVerifier
	_ = did.StaticBlockProvider{}
	_ = did.PKHVerifierOptions{}
	_ = did.ExecutorClient{}
	_ = envelope.SigAlgoEIP1271
	_ signatures.EthereumRPCClient                = (*signatures.StubEthereumRPC)(nil)
	_ attestation.SignatureVerifier               = (*did.VerifierRegistry)(nil)
	_ attestation.SignatureVerifierWithReceipt    = (*did.VerifierRegistry)(nil)
	_                                             = sdktypes.ZeroWeb3VerificationReceipt
)

// ─── byte-equality helper ────────────────────────────────

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
