// FILE PATH: tests/contracts/scw_quorum_helpers_test.go
//
// DESCRIPTION:
//
//	Shared test helpers for v1.7.1 EIP-1271 / smart-contract-wallet
//	verification. The v1.7.x SDK changed the PKHVerifier wire path
//	in two ways the previous SDK seam did NOT exercise:
//
//	  1. Multicall3 aggregate3 wrapping. Every isValidSignature call
//	     is now packed into a single multicall3.aggregate3 calldata
//	     blob and sent to the canonical Multicall3 deployer address
//	     (0xcA11bde05977b3631167028862bE2a173976CA11) — NOT to the
//	     wallet contract directly. Stubs bind against that address
//	     and decode the wrapper.
//	  2. K-of-N executor consensus. PKHVerifierOptions requires
//	     QuorumK ≥ 2 and len(Executors) ≥ QuorumK. Tests construct
//	     two stub EthereumRPC clients bound identically; the
//	     verifier fans out and requires both to agree.
//
//	The helpers in this file mirror the SDK's own matrix-test
//	pattern verbatim (see
//	attesta/tests/verify_entry_signatures_matrix_test.go) so the
//	JN tests assert the production SDK seam and not a parallel
//	encoder that could drift.
//
// KEY DEPENDENCIES:
//   - attesta/crypto/multicall3: PackAggregate3 + BuildEIP1271Calls.
//   - attesta/crypto/signatures: StubEthereumRPC + Multicall3CanonicalAddressHex.
//   - attesta/did: PKHVerifierOptions, ExecutorClient, StaticBlockProvider,
//     DefaultVerifierRegistry.
package contracts

import (
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/multicall3"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/did"

	"github.com/clearcompass-ai/judicial-network/internal/testutil"
)

// scwTestChainID is the CAIP-2 chain identifier the SCW tests pin to.
// 1 = Ethereum mainnet; the value is opaque to the stubs but flows
// into Web3VerificationReceipt.ChainID so receipt-level assertions
// can pin against it.
const scwTestChainID uint64 = 1

// scwTestBlockNumber is the pinned block height for StaticBlockProvider.
// Non-zero (a real Ethereum block) so the verifier doesn't reject the
// pin as the zero-block sentinel.
const scwTestBlockNumber uint64 = 0x10A4B7C

// scwTestBlockHash is the pinned block hash for StaticBlockProvider.
// Distinct first-byte values so a print of the receipt is visually
// distinguishable from RootHash / SMTRoot.
var scwTestBlockHash = [32]byte{0xDE, 0xAD, 0xBE, 0xEF}

// scwSingleCheckCalldata packs a single EIP-1271 check via Multicall3
// aggregate3. This is the calldata the v1.7.1 PKHVerifier sends to
// the Multicall3 deployer; stubs bind against it verbatim.
func scwSingleCheckCalldata(
	addr [signatures.EthereumAddressLen]byte,
	hash [32]byte,
	contractSig []byte,
) []byte {
	check := multicall3.EIP1271Check{
		Address:   addr,
		Hash:      hash,
		Signature: contractSig,
	}
	return multicall3.PackAggregate3(multicall3.BuildEIP1271Calls([]multicall3.EIP1271Check{check}))
}

// scwTwoStubPKHOptions constructs a PKHVerifierOptions configured for
// SCW (EIP-1271) verification with K=2 executor consensus. The two
// returned stubs are bound identically by callers so the SDK's fan-
// out always reaches consensus; callers may also bind divergent
// responses to exercise no-consensus / divergence paths.
//
// NOTE: K=2 is the SDK minimum (QuorumK >= 2 per PKHVerifierOptions
// docstring); JN tests use the minimum to keep the stub-coordination
// surface small.
func scwTwoStubPKHOptions(rpc1, rpc2 *signatures.StubEthereumRPC) did.PKHVerifierOptions {
	return did.PKHVerifierOptions{
		ChainID: scwTestChainID,
		Executors: []did.ExecutorClient{
			{ID: "stub-reth", RPC: rpc1},
			{ID: "stub-erigon", RPC: rpc2},
		},
		QuorumK: 2,
		BlockProvider: did.StaticBlockProvider{
			BlockNumber: scwTestBlockNumber,
			BlockHash:   scwTestBlockHash,
		},
	}
}

// scwQuorumRegistry constructs a DefaultVerifierRegistry bound to
// `destination` with EIP-1271 K=2 consensus enabled. Returns the
// registry plus both stubs so callers can program bindings AFTER
// construction and assert CallCount per-stub.
//
// The returned stubs are independent *signatures.StubEthereumRPC
// values; callers MUST call BindEthCall / BindEthCallError on BOTH
// so the K=2 quorum reaches consensus. A single bound stub yields
// ErrQuorumNoConsensus on verify.
func scwQuorumRegistry(
	t *testing.T,
	destination string,
	resolver did.DIDResolver,
) (*did.VerifierRegistry, *signatures.StubEthereumRPC, *signatures.StubEthereumRPC) {
	t.Helper()
	rpc1 := signatures.NewStubEthereumRPC()
	rpc2 := signatures.NewStubEthereumRPC()
	registry, err := did.DefaultVerifierRegistry(destination, resolver, scwTwoStubPKHOptions(rpc1, rpc2))
	if err != nil {
		t.Fatalf("DefaultVerifierRegistry: %v", err)
	}
	return registry, rpc1, rpc2
}

// scwBindAggregate3Response binds an identical aggregate3 success
// response to both stubs. Use for happy-path / magic-value tests.
func scwBindAggregate3Response(
	rpc1, rpc2 *signatures.StubEthereumRPC,
	calldata []byte,
	innerReturn []byte,
) {
	resp := testutil.EncodeAggregate3Response(true, innerReturn)
	multicallAddr := testutil.Multicall3Addr()
	rpc1.BindEthCall(multicallAddr, calldata, resp)
	rpc2.BindEthCall(multicallAddr, calldata, resp)
}

// scwBindAggregate3Failure binds an aggregate3 response where the
// per-call success flag is false (i.e., the wallet's
// isValidSignature reverted inside multicall3). Both stubs return
// the same per-call failure so K=2 consensus is satisfied; the
// PKHVerifier surfaces ErrEthCallReverted from the inner failure.
func scwBindAggregate3Failure(
	rpc1, rpc2 *signatures.StubEthereumRPC,
	calldata []byte,
) {
	// Per-call success=false with empty inner return — the canonical
	// "wallet reverted" shape.
	resp := testutil.EncodeAggregate3Response(false, nil)
	multicallAddr := testutil.Multicall3Addr()
	rpc1.BindEthCall(multicallAddr, calldata, resp)
	rpc2.BindEthCall(multicallAddr, calldata, resp)
}

// scwBindAggregate3CallError binds the same transport-level error
// to both stubs (e.g., signatures.ErrEthCallReverted from the
// outer aggregate3 wrapper, simulating Multicall3 itself reverting).
// Both stubs return the same error so K=2 consensus is satisfied on
// the failure mode.
func scwBindAggregate3CallError(
	rpc1, rpc2 *signatures.StubEthereumRPC,
	calldata []byte,
	err error,
) {
	multicallAddr := testutil.Multicall3Addr()
	rpc1.BindEthCallError(multicallAddr, calldata, err)
	rpc2.BindEthCallError(multicallAddr, calldata, err)
}
