/*
FILE PATH: cmd/network-api/signature_verifier.go

DESCRIPTION:

	Composition root for the JN signature verifier consumed by the
	verification service's Path C admission gate (/v1/verify/complete,
	api/verification ServerConfig.SignatureVerifier).

	This is where attesta v1.11.1's native receipt-aware, multi-chain
	verifier is assembled. The result is a *did.VerifierRegistry,
	which implements both attestation.SignatureVerifier and
	attestation.SignatureVerifierWithReceipt — so the SDK's
	attestation.VerifyEntrySignatures collects per-signature
	Web3VerificationReceipts without the verification handler touching
	DID-method internals (SDK Principle 1 — the consumer reads
	receipts, never iterates signatures).

	# MODES

	EOA-only (SmartContractWallet.Enabled == false):
	  did:key, did:pkh-EOA (ECDSA / EIP-191 / EIP-712), and did:web
	  verify pure-CPU and chain-agnostically. SigAlgoEIP1271 is
	  rejected. No Ethereum RPC is consulted. The "pkh" method is a
	  single EOA-only PKHVerifier.

	EIP-1271 multi-chain (SmartContractWallet.Enabled == true):
	  one PKHVerifier per onboarded chain, wrapped in a
	  did.MultiChainPKHVerifier registered as the "pkh" method. Each
	  chain's PKHVerifier fans isValidSignature to that chain's
	  executor quorum (one Multicall3.aggregate3 per executor), pinned
	  to a (BlockNumber, BlockHash) from that chain's head-tracking
	  ethBlockProvider. The router dispatches did:pkh:eip155:<chain>
	  to the owning chain and fail-closes (did.ErrChainNotConfigured)
	  on un-onboarded chains. The per-chain PKHVerifier itself rejects
	  a DID whose chain reference differs from its ChainID
	  (did.ErrChainIDMismatch) — closing the cross-chain replay vector
	  (Polygon Safe signature replayed against a Mainnet RPC at the
	  same CREATE2 address). Both checks live in the SDK; JN only
	  wires the per-chain map.

	# WHY UNBOUND REGISTRY

	The registry is constructed via NewVerifierRegistry (unbound), NOT
	DefaultVerifierRegistry (destination-bound). JN is multi-tenant —
	one verifier serves every destination — and the Path C composite
	verifies via registry.Verify (per-signature), which has no
	destination concept. Per-entry destination cross-checks are
	enforced by JN's own Origin/Destination stage.

KEY DEPENDENCIES:
  - attesta/did: NewVerifierRegistry, NewKeyVerifier, NewWebVerifier,
    NewPKHVerifier, PKHVerifierOptions, ExecutorClient,
    NewMultiChainPKHVerifier.
  - attesta/crypto/signatures: NewHTTPEthereumRPC.
  - attesta/attestation: SignatureVerifier (return type).
*/
package main

import (
	"fmt"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/did"

	"github.com/clearcompass-ai/judicial-network/api/config"
)

// buildSignatureVerifier assembles the native v1.11.1 signature
// verifier from operational config + the shared DID resolver. The
// returned value is the *did.VerifierRegistry threaded into
// api/verification ServerConfig.SignatureVerifier; it satisfies both
// attestation.SignatureVerifier and SignatureVerifierWithReceipt.
//
// resolver MUST be non-nil (the did:web verifier requires it; the
// binary's buildDIDResolver always supplies one).
func buildSignatureVerifier(cfg config.Operational, resolver did.DIDResolver) (attestation.SignatureVerifier, error) {
	if resolver == nil {
		return nil, fmt.Errorf("buildSignatureVerifier: nil resolver")
	}

	pkh, err := buildPKHVerifier(cfg.SmartContractWallet)
	if err != nil {
		return nil, err
	}

	registry := did.NewVerifierRegistry()
	if err := registry.Register("pkh", pkh); err != nil {
		return nil, fmt.Errorf("buildSignatureVerifier: register pkh: %w", err)
	}
	if err := registry.Register("key", did.NewKeyVerifier()); err != nil {
		return nil, fmt.Errorf("buildSignatureVerifier: register key: %w", err)
	}
	if err := registry.Register("web", did.NewWebVerifier(resolver)); err != nil {
		return nil, fmt.Errorf("buildSignatureVerifier: register web: %w", err)
	}
	return registry, nil
}

// buildPKHVerifier returns the "pkh" method verifier: an EOA-only
// PKHVerifier when SCW is disabled, or a MultiChainPKHVerifier over
// one PKHVerifier per onboarded chain when enabled.
func buildPKHVerifier(scw config.SmartContractWalletConfig) (did.SignatureVerifier, error) {
	if !scw.Enabled {
		// EOA-only: zero options → chain-agnostic EOA, EIP-1271 rejected.
		v, err := did.NewPKHVerifier(did.PKHVerifierOptions{})
		if err != nil {
			return nil, fmt.Errorf("buildPKHVerifier: EOA-only verifier: %w", err)
		}
		return v, nil
	}

	byChain := make(map[uint64]*did.PKHVerifier, len(scw.Chains))
	for _, chain := range scw.Chains {
		v, err := buildChainPKHVerifier(scw, chain)
		if err != nil {
			return nil, fmt.Errorf("buildPKHVerifier: chain %d: %w", chain.ChainID, err)
		}
		byChain[chain.ChainID] = v
	}
	mc, err := did.NewMultiChainPKHVerifier(byChain)
	if err != nil {
		return nil, fmt.Errorf("buildPKHVerifier: multi-chain router: %w", err)
	}
	return mc, nil
}

// buildChainPKHVerifier constructs one chain's EIP-1271 PKHVerifier:
// its executor quorum + a head-tracking block provider over the
// chain's own EthRPCEndpoint.
func buildChainPKHVerifier(scw config.SmartContractWalletConfig, chain config.ChainQuorumConfig) (*did.PKHVerifier, error) {
	executors, err := buildExecutorClients(scw, chain)
	if err != nil {
		return nil, err
	}
	blockProvider, err := newEthBlockProvider(
		chain.EthRPCEndpoint,
		chain.EffectiveConfirmationDepth(),
		scw.EffectiveRPCTimeout(),
		scw.AllowInsecureHTTP,
	)
	if err != nil {
		return nil, fmt.Errorf("block provider: %w", err)
	}
	v, err := did.NewPKHVerifier(did.PKHVerifierOptions{
		ChainID:       chain.ChainID,
		Executors:     executors,
		QuorumK:       uint8(chain.QuorumK),
		BlockProvider: blockProvider,
	})
	if err != nil {
		return nil, fmt.Errorf("pkh verifier: %w", err)
	}
	return v, nil
}

// buildExecutorClients constructs one SDK HTTPEthereumRPC per executor
// in the chain's quorum. The executor set is exactly chain.Executors
// (config validation guarantees >= 2 entries, unique non-empty IDs,
// and https-or-opt-in endpoints).
func buildExecutorClients(scw config.SmartContractWalletConfig, chain config.ChainQuorumConfig) ([]did.ExecutorClient, error) {
	opts := []signatures.HTTPRPCOption{
		signatures.WithTimeout(scw.EffectiveRPCTimeout()),
	}
	if scw.AllowInsecureHTTP {
		opts = append(opts, signatures.WithAllowInsecureHTTP(true))
	}
	out := make([]did.ExecutorClient, 0, len(chain.Executors))
	for i, ex := range chain.Executors {
		rpc, err := signatures.NewHTTPEthereumRPC(ex.Endpoint, opts...)
		if err != nil {
			return nil, fmt.Errorf("executor[%d] %q: %w", i, ex.ID, err)
		}
		out = append(out, did.ExecutorClient{ID: ex.ID, RPC: rpc})
	}
	return out, nil
}
