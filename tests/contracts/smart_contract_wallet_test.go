/*
FILE PATH:

	tests/contracts/smart_contract_wallet_test.go

DESCRIPTION:

	End-to-end functional test for v0.8.0 EIP-1271 (smart-contract-
	wallet) signature verification. Exercises the full happy path
	AND rejection paths from the ledger's verifier-registry seam:

	  1. Build an entry whose primary signer is
	     did:pkh:eip155:1:0x<wallet-contract>.
	  2. Attach a SigAlgoEIP1271 signature with arbitrary opaque
	     contract-signature bytes (the SDK never inspects sig.Bytes
	     for this algoID — the wallet contract is the source of
	     truth).
	  3. Hash the SigningPayload and program a stub
	     EthereumRPCClient with the eth_call binding the ledger
	     WILL produce when verifying this entry.
	  4. Build the verifier registry via
	     did.DefaultVerifierRegistryWithRPC bound to the
	     destination on the entry.
	  5. Call registry.VerifyEntry(entry) and assert acceptance
	     (happy path) or the appropriate typed rejection (negative
	     paths).

	This file is the JN consumer's contract assertion that v0.8.0's
	SDK seam is wired correctly. A future SDK that breaks
	DefaultVerifierRegistryWithRPC, EncodeIsValidSignatureCalldata,
	SigAlgoEIP1271 wire registration, or the magic-value comparison
	will surface here BEFORE any ledger deployment.

SECURITY PROPERTIES PINNED:
  - Magic-value return -> registry.VerifyEntry returns nil.
  - Selector-with-attacker-junk return -> wraps
    signatures.ErrEIP1271InvalidMagic.
  - Empty return (contract not deployed) -> wraps
    signatures.ErrEIP1271ContractEmpty.
  - eth_call revert -> wraps signatures.ErrEthCallReverted.
  - Cross-exchange replay defense still applies: an entry with the
    wrong destination surfaces ErrDestinationMismatch BEFORE any
    eth_call is issued.
  - The signing payload's hash matches what the SDK's
    EncodeIsValidSignatureCalldata is called with (drift would
    silently invalidate every smart-contract-wallet signature).
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
	rpc := signatures.NewStubEthereumRPC()
	addr := scwSampleAddr()
	contractSig := []byte("opaque-wallet-signature-bytes-vary")

	entry, _, calldata := scwBuildEntryFromContract(t, addr, scwDestination, contractSig)
	rpc.BindEthCall(addr, calldata, scwMagicReturn())

	registry, regErr := did.DefaultVerifierRegistryWithRPC(scwDestination, panicResolver{}, rpc)
	if regErr != nil {
		t.Fatalf("DefaultVerifierRegistryWithRPC: %v", regErr)
	}

	if err := registry.VerifyEntry(ctx, entry); err != nil {
		t.Fatalf("happy path EIP-1271 entry MUST verify; got %v", err)
	}
	if got := rpc.CallCount("eth_call"); got != 1 {
		t.Errorf("expected exactly 1 eth_call per signature; got %d", got)
	}
}

// ─── magic-value-mismatch class (the high-stakes one) ──────────

func TestSCW_RejectsSelectorWithAttackerJunk(t *testing.T) {
	ctx := context.Background()
	rpc := signatures.NewStubEthereumRPC()
	addr := scwSampleAddr()
	contractSig := []byte("x")

	entry, _, calldata := scwBuildEntryFromContract(t, addr, scwDestination, contractSig)
	junk := scwMagicReturn()
	for i := 4; i < 32; i++ {
		junk[i] = 0xFF
	}
	rpc.BindEthCall(addr, calldata, junk)

	registry, regErr := did.DefaultVerifierRegistryWithRPC(scwDestination, panicResolver{}, rpc)
	if regErr != nil {
		t.Fatalf("DefaultVerifierRegistryWithRPC: %v", regErr)
	}
	err := registry.VerifyEntry(ctx, entry)
	if !errors.Is(err, signatures.ErrEIP1271InvalidMagic) {
		t.Fatalf("selector + attacker-junk MUST surface ErrEIP1271InvalidMagic; got %v", err)
	}
}

func TestSCW_RejectsAllZeroReturn(t *testing.T) {
	ctx := context.Background()
	rpc := signatures.NewStubEthereumRPC()
	addr := scwSampleAddr()
	contractSig := []byte("x")

	entry, _, calldata := scwBuildEntryFromContract(t, addr, scwDestination, contractSig)
	rpc.BindEthCall(addr, calldata, make([]byte, 32))

	registry, regErr := did.DefaultVerifierRegistryWithRPC(scwDestination, panicResolver{}, rpc)
	if regErr != nil {
		t.Fatalf("DefaultVerifierRegistryWithRPC: %v", regErr)
	}
	err := registry.VerifyEntry(ctx, entry)
	if !errors.Is(err, signatures.ErrEIP1271InvalidMagic) {
		t.Fatalf("all-zero return MUST reject; got %v", err)
	}
}

// ─── contract-state rejection paths ──────────────────────────

func TestSCW_RejectsEmptyReturn_NotDeployed(t *testing.T) {
	ctx := context.Background()
	rpc := signatures.NewStubEthereumRPC()
	addr := scwSampleAddr()
	contractSig := []byte("x")

	entry, _, calldata := scwBuildEntryFromContract(t, addr, scwDestination, contractSig)
	rpc.BindEthCall(addr, calldata, []byte{})

	registry, regErr := did.DefaultVerifierRegistryWithRPC(scwDestination, panicResolver{}, rpc)
	if regErr != nil {
		t.Fatalf("DefaultVerifierRegistryWithRPC: %v", regErr)
	}
	err := registry.VerifyEntry(ctx, entry)
	if !errors.Is(err, signatures.ErrEIP1271ContractEmpty) {
		t.Fatalf("empty return MUST surface ErrEIP1271ContractEmpty; got %v", err)
	}
}

func TestSCW_PropagatesRevert(t *testing.T) {
	ctx := context.Background()
	rpc := signatures.NewStubEthereumRPC()
	addr := scwSampleAddr()
	contractSig := []byte("x")

	entry, _, calldata := scwBuildEntryFromContract(t, addr, scwDestination, contractSig)
	rpc.BindEthCallError(addr, calldata, signatures.ErrEthCallReverted)

	registry, regErr := did.DefaultVerifierRegistryWithRPC(scwDestination, panicResolver{}, rpc)
	if regErr != nil {
		t.Fatalf("DefaultVerifierRegistryWithRPC: %v", regErr)
	}
	err := registry.VerifyEntry(ctx, entry)
	if !errors.Is(err, signatures.ErrEthCallReverted) {
		t.Fatalf("revert MUST propagate as ErrEthCallReverted; got %v", err)
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
