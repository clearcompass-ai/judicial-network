// FILE PATH: api/config/scw.go
//
// DESCRIPTION:
//
//	Smart-contract-wallet (EIP-1271) verification configuration. The
//	attesta v1.7.1 PKHVerifier verifies EIP-1271 signatures with
//	K-of-N executor consensus pinned to a specific (BlockNumber,
//	BlockHash) — Trust Alignment 2 (the K-of-N Oracle) and SDK
//	Principle 9 (Zero-Trust Identity Agnosticism: did:pkh smart-
//	contract wallets are first-class peers).
//
//	The zero value of SmartContractWalletConfig (Enabled=false)
//	means EOA-only verification: did:key, did:pkh-EOA (ECDSA /
//	EIP-191 / EIP-712), and did:web all verify pure-CPU, while
//	SigAlgoEIP1271 entries are rejected with ErrAlgorithmNotSupported.
//	Deployments that admit smart-contract-wallet signers set
//	Enabled=true and declare a quorum of >= 2 independent executor
//	RPC endpoints.
//
// KEY DEPENDENCIES:
//   - attesta/types: MaxExecutorQuorumClients (16),
//     MaxExecutorClientIDLen (64) — the SDK's executor-set bounds.
package config

import (
	"fmt"
	"strings"
	"time"

	sdktypes "github.com/clearcompass-ai/attesta/types"
)

// DefaultSCWRPCTimeout is the per-request timeout applied to each
// executor's eth_call and to the block-pin RPC when the SCW config
// leaves RPCTimeout zero.
const DefaultSCWRPCTimeout = 5 * time.Second

// DefaultSCWConfirmationDepth is the default number of blocks behind
// the chain head the BlockProvider pins to when ConfirmationDepth is
// zero. 12 blocks is the conventional Ethereum-mainnet finality
// heuristic — deep enough that a pinned block is extremely unlikely
// to be reorged out from under an in-flight verification batch.
const DefaultSCWConfirmationDepth uint64 = 12

// ExecutorEndpoint is one independent Ethereum JSON-RPC backend in
// the EIP-1271 executor quorum. Each executor SHOULD be a distinct
// client implementation on independent infrastructure (e.g., Reth +
// Erigon + Nethermind) so a single compromised or buggy archive
// node cannot poison the transparency log.
type ExecutorEndpoint struct {
	// ID is the operator-declared identifier of this executor
	// (e.g., "reth-us-east-1a"). Non-empty, unique within the
	// quorum, and <= types.MaxExecutorClientIDLen bytes. Flows
	// verbatim into the Web3VerificationReceipt's per-executor
	// attestation.
	ID string `json:"id"`

	// Endpoint is the JSON-RPC URL. https:// required unless the
	// parent config sets AllowInsecureHTTP (local-dev only).
	Endpoint string `json:"endpoint"`
}

// SmartContractWalletConfig configures EIP-1271 K-of-N executor
// consensus for the binary's signature verifier.
type SmartContractWalletConfig struct {
	// Enabled is the master switch. When false (the default), the
	// signature verifier runs EOA-only and SigAlgoEIP1271 entries
	// are rejected. Set true to admit smart-contract-wallet signers.
	Enabled bool `json:"enabled"`

	// ChainID is the CAIP-2 / EIP-155 chain identifier the executors
	// target (1 = Ethereum mainnet, 137 = Polygon, 8453 = Base).
	// Required when Enabled. Embedded in every receipt.
	ChainID uint64 `json:"chain_id"`

	// Executors is the quorum of independent RPC backends consulted
	// per EIP-1271 verification — this is exactly the executor set
	// handed to the SDK PKHVerifier. Required when Enabled, with
	// len >= 2, len >= QuorumK, and len <=
	// types.MaxExecutorQuorumClients. Each executor SHOULD be a
	// distinct client implementation on independent infrastructure.
	// The top-level Operational.EthRPCEndpoint is NOT added here —
	// it serves the separate head-tracking block-pin role.
	Executors []ExecutorEndpoint `json:"executors,omitempty"`

	// QuorumK is the minimum count of executors that MUST agree on
	// the same canonical eth_call result for a verdict to be
	// accepted. Required when Enabled, with 2 <= QuorumK <=
	// len(Executors). The SDK rejects QuorumK < 2 — a single
	// executor offers no Byzantine-fault protection.
	QuorumK int `json:"quorum_k"`

	// ConfirmationDepth is the number of blocks behind the chain
	// head the BlockProvider pins to. Zero applies
	// DefaultSCWConfirmationDepth (12). A deeper depth trades
	// verification latency for stronger reorg resistance.
	ConfirmationDepth uint64 `json:"confirmation_depth,omitempty"`

	// RPCTimeout caps each executor eth_call and the block-pin RPC.
	// Zero applies DefaultSCWRPCTimeout (5s).
	RPCTimeout time.Duration `json:"rpc_timeout,omitempty"`

	// AllowInsecureHTTP opts in to http:// executor endpoints.
	// Local-dev only; production MUST keep this false (the SDK's
	// HTTP RPC client rejects http:// without the matching opt-in).
	AllowInsecureHTTP bool `json:"allow_insecure_http,omitempty"`
}

// EffectiveRPCTimeout returns the configured RPCTimeout or the
// default when unset.
func (c SmartContractWalletConfig) EffectiveRPCTimeout() time.Duration {
	if c.RPCTimeout <= 0 {
		return DefaultSCWRPCTimeout
	}
	return c.RPCTimeout
}

// EffectiveConfirmationDepth returns the configured ConfirmationDepth
// or the default when unset.
func (c SmartContractWalletConfig) EffectiveConfirmationDepth() uint64 {
	if c.ConfirmationDepth == 0 {
		return DefaultSCWConfirmationDepth
	}
	return c.ConfirmationDepth
}

// validate enforces the EIP-1271 quorum invariants at boot. A
// disabled config is always valid (EOA-only verification has no
// executor requirements). Mirrors the SDK's PKHVerifierOptions
// construction checks so misconfiguration fails at boot rather than
// on the first smart-contract-wallet entry.
func (c SmartContractWalletConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if c.ChainID == 0 {
		return fmt.Errorf("%w: SmartContractWallet.ChainID required when enabled", ErrInvalidConfig)
	}
	if len(c.Executors) == 0 {
		return fmt.Errorf("%w: SmartContractWallet.Executors required when enabled (>= 2 for K-of-N)", ErrInvalidConfig)
	}
	if len(c.Executors) > sdktypes.MaxExecutorQuorumClients {
		return fmt.Errorf("%w: SmartContractWallet.Executors length %d exceeds SDK max %d",
			ErrInvalidConfig, len(c.Executors), sdktypes.MaxExecutorQuorumClients)
	}
	if c.QuorumK < 2 {
		return fmt.Errorf("%w: SmartContractWallet.QuorumK must be >= 2 (got %d); a single executor offers no Byzantine-fault protection",
			ErrInvalidConfig, c.QuorumK)
	}
	if c.QuorumK > len(c.Executors) {
		return fmt.Errorf("%w: SmartContractWallet.QuorumK %d exceeds executor count %d",
			ErrInvalidConfig, c.QuorumK, len(c.Executors))
	}
	seen := make(map[string]struct{}, len(c.Executors))
	for i, ex := range c.Executors {
		if ex.ID == "" {
			return fmt.Errorf("%w: SmartContractWallet.Executors[%d].ID required", ErrInvalidConfig, i)
		}
		if len(ex.ID) > sdktypes.MaxExecutorClientIDLen {
			return fmt.Errorf("%w: SmartContractWallet.Executors[%d].ID exceeds SDK max %d bytes",
				ErrInvalidConfig, i, sdktypes.MaxExecutorClientIDLen)
		}
		if _, dup := seen[ex.ID]; dup {
			return fmt.Errorf("%w: SmartContractWallet.Executors[%d].ID %q duplicated", ErrInvalidConfig, i, ex.ID)
		}
		seen[ex.ID] = struct{}{}
		if ex.Endpoint == "" {
			return fmt.Errorf("%w: SmartContractWallet.Executors[%d].Endpoint required", ErrInvalidConfig, i)
		}
		if strings.HasPrefix(strings.ToLower(ex.Endpoint), "http://") && !c.AllowInsecureHTTP {
			return fmt.Errorf("%w: SmartContractWallet.Executors[%d].Endpoint is http:// but AllowInsecureHTTP is false",
				ErrInvalidConfig, i)
		}
	}
	return nil
}
