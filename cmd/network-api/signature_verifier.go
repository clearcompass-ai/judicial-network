/*
FILE PATH: cmd/network-api/signature_verifier.go

DESCRIPTION:

	Composition root for the JN signature verifier consumed by the
	verification service's Path C admission gate (/v1/verify/complete,
	api/verification ServerConfig.SignatureVerifier).

	This is where attesta v1.7.1's native receipt-aware verifier is
	assembled. The result is a *did.VerifierRegistry, which implements
	both attestation.SignatureVerifier and
	attestation.SignatureVerifierWithReceipt — so the SDK's
	attestation.VerifyEntrySignatures collects per-signature
	Web3VerificationReceipts without the verification handler touching
	DID-method internals (SDK Principle 1 — the consumer reads
	receipts, never iterates signatures).

	# MODES

	EOA-only (SmartContractWallet.Enabled == false):
	  did:key, did:pkh-EOA (ECDSA / EIP-191 / EIP-712), and did:web
	  verify pure-CPU. SigAlgoEIP1271 entries are rejected with
	  ErrAlgorithmNotSupported. No Ethereum RPC is consulted.

	EIP-1271 K-of-N (SmartContractWallet.Enabled == true):
	  adds smart-contract-wallet verification. Every isValidSignature
	  call fans out to the operator-declared executor quorum via the
	  SDK's QuorumRPCClient (one Multicall3.aggregate3 per executor),
	  pinned to a (BlockNumber, BlockHash) supplied by the head-
	  tracking ethBlockProvider. K-of-N agreement is required (Trust
	  Alignment 2 — the K-of-N Oracle). The executor set is exactly
	  SmartContractWallet.Executors (>= 2, validated at config load);
	  the top-level EthRPCEndpoint is the head-tracking block-pin
	  source, a role distinct from the verification quorum.

	# WHY UNBOUND

	The registry is constructed via NewVerifierRegistry (unbound),
	NOT DefaultVerifierRegistry (destination-bound). JN is multi-
	tenant — one verifier serves every destination — and the Path C
	composite verifies via registry.Verify (per-signature), which has
	no destination concept. Per-entry destination cross-checks are
	enforced by JN's own Origin/Destination stage, not by the
	verifier's registry binding.

KEY DEPENDENCIES:
  - attesta/did: NewVerifierRegistry, NewKeyVerifier, NewWebVerifier,
    NewPKHVerifier, PKHVerifierOptions, ExecutorClient.
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

// buildSignatureVerifier assembles the native v1.7.1 signature
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

	pkhOpts, err := buildPKHVerifierOptions(cfg)
	if err != nil {
		return nil, err
	}
	pkh, err := did.NewPKHVerifier(pkhOpts)
	if err != nil {
		return nil, fmt.Errorf("buildSignatureVerifier: pkh verifier: %w", err)
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

// buildPKHVerifierOptions returns the zero options (EOA-only) when
// SmartContractWallet is disabled, or a fully-populated EIP-1271
// K-of-N options bundle otherwise. The executor quorum is exactly
// SmartContractWallet.Executors; the BlockProvider is a head-tracking
// ethBlockProvider over the top-level EthRPCEndpoint.
func buildPKHVerifierOptions(cfg config.Operational) (did.PKHVerifierOptions, error) {
	scw := cfg.SmartContractWallet
	if !scw.Enabled {
		// EOA-only: the zero value disables EIP-1271 by construction.
		return did.PKHVerifierOptions{}, nil
	}

	executors, err := buildExecutorClients(scw)
	if err != nil {
		return did.PKHVerifierOptions{}, err
	}

	blockProvider, err := newEthBlockProvider(
		cfg.EthRPCEndpoint,
		scw.EffectiveConfirmationDepth(),
		scw.EffectiveRPCTimeout(),
		scw.AllowInsecureHTTP,
	)
	if err != nil {
		return did.PKHVerifierOptions{}, fmt.Errorf("buildPKHVerifierOptions: block provider: %w", err)
	}

	return did.PKHVerifierOptions{
		ChainID:       scw.ChainID,
		Executors:     executors,
		QuorumK:       uint8(scw.QuorumK),
		BlockProvider: blockProvider,
	}, nil
}

// buildExecutorClients constructs one SDK HTTPEthereumRPC per
// operator-declared executor. The executor set is exactly
// scw.Executors (config validation already guarantees >= 2 entries,
// unique non-empty IDs, and https-or-opt-in endpoints).
func buildExecutorClients(scw config.SmartContractWalletConfig) ([]did.ExecutorClient, error) {
	opts := []signatures.HTTPRPCOption{
		signatures.WithTimeout(scw.EffectiveRPCTimeout()),
	}
	if scw.AllowInsecureHTTP {
		opts = append(opts, signatures.WithAllowInsecureHTTP(true))
	}

	out := make([]did.ExecutorClient, 0, len(scw.Executors))
	for i, ex := range scw.Executors {
		rpc, err := signatures.NewHTTPEthereumRPC(ex.Endpoint, opts...)
		if err != nil {
			return nil, fmt.Errorf("buildExecutorClients: executor[%d] %q: %w", i, ex.ID, err)
		}
		out = append(out, did.ExecutorClient{ID: ex.ID, RPC: rpc})
	}
	return out, nil
}
