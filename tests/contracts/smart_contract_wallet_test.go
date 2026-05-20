/*
FILE PATH:

	tests/contracts/smart_contract_wallet_test.go

DESCRIPTION:

	End-to-end functional test for v1.7.1 EIP-1271 (smart-contract-
	wallet) signature verification. Exercises the full happy path
	AND rejection paths from the ledger's verifier-registry seam:

	  1. Build an entry whose primary signer is
	     did:pkh:eip155:1:0x<wallet-contract>.
	  2. Attach a SigAlgoEIP1271 signature with arbitrary opaque
	     contract-signature bytes (the SDK never inspects sig.Bytes
	     for this algoID — the wallet contract is the source of
	     truth).
	  3. Hash the SigningPayload, pack the (addr, hash, sig) check
	     through Multicall3.aggregate3, and program a 2-stub K=2
	     executor quorum with the aggregate3 calldata bound to the
	     canonical Multicall3 deployer address.
	  4. Build the verifier registry via
	     did.DefaultVerifierRegistry with a PKHVerifierOptions
	     declaring (ChainID, Executors, QuorumK=2, BlockProvider).
	  5. Call registry.VerifyEntry(entry) and assert acceptance
	     (happy path) or the appropriate typed rejection (negative
	     paths).

	This file is the JN consumer's contract assertion that v1.7.1's
	SDK seam is wired correctly. A future SDK that breaks
	DefaultVerifierRegistry, the Multicall3 aggregate3 packing,
	SigAlgoEIP1271 wire registration, or the magic-value comparison
	will surface here BEFORE any ledger deployment.

SECURITY PROPERTIES PINNED (v1.7.1 K-of-N consensus semantics):
  - Magic-value inner return, K executors agree -> VerifyEntry nil.
  - Non-magic inner return (attacker junk / all-zero / per-call
    failure), K executors AGREE it is invalid -> wraps
    did.ErrExecutorQuorumDisagreesOnInvalid ("the contract
    definitively says invalid").
  - No K-of-N consensus (outer revert / divergent nodes / unbound
    calldata) -> wraps did.ErrExecutorQuorumNotReached.
  - Cross-exchange replay defense still applies: an entry with the
    wrong destination surfaces ErrDestinationMismatch BEFORE any
    eth_call is issued.
  - K=2 executor consensus: BOTH stubs are called per verification
    (Trust Alignment 2 — K-of-N Oracle at the RPC trust boundary).
*/
package contracts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/did"
)

// ─── helpers ─────────────────────────────────────────

// scwSampleAddr returns a deterministic 20-byte Ethereum contract
// address used as the wallet contract's address.
func scwSampleAddr() [signatures.EthereumAddressLen]byte {
	var a [signatures.EthereumAddressLen]byte
	for i := range a {
		a[i] = byte(0xC0 + i)
	}
	return a
}

// scwDIDForAddr formats the addr as a did:pkh:eip155:1:0x...
func scwDIDForAddr(addr [signatures.EthereumAddressLen]byte) string {
	return "did:pkh:eip155:1:0x" + hex.EncodeToString(addr[:])
}

// scwMagicReturn is the canonical EIP-1271 magic value: 0x1626ba7e
// followed by 28 zero bytes (32-byte ABI-encoded bytes4).
func scwMagicReturn() []byte {
	out := make([]byte, 32)
	out[0], out[1], out[2], out[3] = 0x16, 0x26, 0xba, 0x7e
	return out
}

// scwBuildEntryFromContract builds an entry whose primary signer is
// the wallet contract at addr, and attaches an EIP-1271 signature
// with the given contract-signature bytes.
//
// Returns the entry, the signing-payload hash that the verifier will
// pass to isValidSignature, and the calldata for the eth_call (so
// the test can program the stub deterministically).
func scwBuildEntryFromContract(
	t *testing.T,
	addr [signatures.EthereumAddressLen]byte,
	destination string,
	contractSig []byte,
) (*envelope.Entry, [32]byte, []byte) {
	t.Helper()

	signerDID := scwDIDForAddr(addr)
	auth := envelope.AuthoritySameSigner
	header := envelope.ControlHeader{
		Destination:   destination,
		SignerDID:     signerDID,
		AuthorityPath: &auth,
	}
	payload := []byte(`{"test":"smart-contract-wallet"}`)
	entry, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = append(entry.Signatures, envelope.Signature{
		SignerDID: signerDID,
		AlgoID:    envelope.SigAlgoEIP1271,
		Bytes:     contractSig,
	})
	if err := entry.Validate(); err != nil {
		t.Fatalf("entry.Validate: %v", err)
	}

	// The verifier hashes envelope.SigningPayload(entry) with sha256
	// and passes the 32-byte digest to isValidSignature. We compute
	// it here so the test knows exactly what calldata to bind.
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	calldata := signatures.EncodeIsValidSignatureCalldata(hash, contractSig)
	return entry, hash, calldata
}

const scwDestination = "did:web:state:tn:davidson"

// ─── happy path: full e2e ────────────────────────────────

func TestSCW_HappyPath_RegistryAccepts(t *testing.T) {
	ctx := context.Background()
	addr := scwSampleAddr()
	contractSig := []byte("opaque-wallet-signature-bytes-vary")

	entry, hash, _ := scwBuildEntryFromContract(t, addr, scwDestination, contractSig)

	registry, rpc1, rpc2 := scwQuorumRegistry(t, scwDestination, panicResolver{})
	calldata := scwSingleCheckCalldata(addr, hash, contractSig)
	scwBindAggregate3Response(rpc1, rpc2, calldata, scwMagicReturn())

	if err := registry.VerifyEntry(ctx, entry); err != nil {
		t.Fatalf("happy path EIP-1271 entry MUST verify; got %v", err)
	}
	// K=2 quorum: BOTH stubs are called for every verification.
	if got := rpc1.CallCount("eth_call"); got != 1 {
		t.Errorf("executor 1 eth_call count = %d, want 1", got)
	}
	if got := rpc2.CallCount("eth_call"); got != 1 {
		t.Errorf("executor 2 eth_call count = %d, want 1", got)
	}
}

// ─── magic-value-mismatch class (the high-stakes one) ──────────

func TestSCW_RejectsSelectorWithAttackerJunk(t *testing.T) {
	ctx := context.Background()
	addr := scwSampleAddr()
	contractSig := []byte("x")

	entry, hash, _ := scwBuildEntryFromContract(t, addr, scwDestination, contractSig)
	junk := scwMagicReturn()
	for i := 4; i < 32; i++ {
		junk[i] = 0xFF
	}

	registry, rpc1, rpc2 := scwQuorumRegistry(t, scwDestination, panicResolver{})
	calldata := scwSingleCheckCalldata(addr, hash, contractSig)
	scwBindAggregate3Response(rpc1, rpc2, calldata, junk)

	// Both executors agree on the same non-magic return → the
	// contract definitively says invalid.
	err := registry.VerifyEntry(ctx, entry)
	if !errors.Is(err, did.ErrExecutorQuorumDisagreesOnInvalid) {
		t.Fatalf("selector + attacker-junk MUST surface ErrExecutorQuorumDisagreesOnInvalid; got %v", err)
	}
}

func TestSCW_RejectsAllZeroReturn(t *testing.T) {
	ctx := context.Background()
	addr := scwSampleAddr()
	contractSig := []byte("x")

	entry, hash, _ := scwBuildEntryFromContract(t, addr, scwDestination, contractSig)

	registry, rpc1, rpc2 := scwQuorumRegistry(t, scwDestination, panicResolver{})
	calldata := scwSingleCheckCalldata(addr, hash, contractSig)
	scwBindAggregate3Response(rpc1, rpc2, calldata, make([]byte, 32))

	// Both executors agree on the all-zero (non-magic) return.
	err := registry.VerifyEntry(ctx, entry)
	if !errors.Is(err, did.ErrExecutorQuorumDisagreesOnInvalid) {
		t.Fatalf("all-zero return MUST surface ErrExecutorQuorumDisagreesOnInvalid; got %v", err)
	}
}

// ─── contract-state rejection paths ──────────────────────────

func TestSCW_RejectsPerCallFailure_NotDeployed(t *testing.T) {
	ctx := context.Background()
	addr := scwSampleAddr()
	contractSig := []byte("x")

	entry, hash, _ := scwBuildEntryFromContract(t, addr, scwDestination, contractSig)

	registry, rpc1, rpc2 := scwQuorumRegistry(t, scwDestination, panicResolver{})
	calldata := scwSingleCheckCalldata(addr, hash, contractSig)
	// Multicall3 marks the inner call as failed (allowFailure=true
	// surfaces per-call success=false with empty inner return) —
	// the canonical "contract not deployed at addr" shape. Both
	// executors agree on the same (success=false, empty) result,
	// which canonicalizes to a non-magic verdict.
	scwBindAggregate3Failure(rpc1, rpc2, calldata)

	err := registry.VerifyEntry(ctx, entry)
	if !errors.Is(err, did.ErrExecutorQuorumDisagreesOnInvalid) {
		t.Fatalf("per-call failure MUST surface ErrExecutorQuorumDisagreesOnInvalid; got %v", err)
	}
}

func TestSCW_OuterRevert_NoConsensus(t *testing.T) {
	ctx := context.Background()
	addr := scwSampleAddr()
	contractSig := []byte("x")

	entry, hash, _ := scwBuildEntryFromContract(t, addr, scwDestination, contractSig)

	registry, rpc1, rpc2 := scwQuorumRegistry(t, scwDestination, panicResolver{})
	calldata := scwSingleCheckCalldata(addr, hash, contractSig)
	// Both executors error at the transport layer — no node returns
	// a usable result, so K-of-N consensus cannot be reached.
	scwBindAggregate3CallError(rpc1, rpc2, calldata, signatures.ErrEthCallReverted)

	err := registry.VerifyEntry(ctx, entry)
	if !errors.Is(err, did.ErrExecutorQuorumNotReached) {
		t.Fatalf("outer aggregate3 revert MUST surface ErrExecutorQuorumNotReached; got %v", err)
	}
}

// panicResolver: did:web is unreachable in every test here (every
// test uses did:pkh). A panicResolver makes that explicit: any
// accidental did:web traffic crashes loud rather than silently
// hitting a real network.
type panicResolver struct{}

func (panicResolver) Resolve(context.Context, string) (*did.DIDDocument, error) {
	panic("scw test: did:web resolution not expected")
}
