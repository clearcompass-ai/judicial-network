// FILE PATH: api/config/scw.go
//
// DESCRIPTION:
//
//	Smart-contract-wallet (EIP-1271) verification configuration.
//	attesta v1.8.0 verifies EIP-1271 signatures with K-of-N executor
//	consensus pinned to a specific (BlockNumber, BlockHash), and binds
//	the DID's eip155 chain to the verifier's chain — closing the
//	cross-chain replay vector (a Polygon Safe signature can no longer
//	be replayed against a Mainnet RPC at the same CREATE2 address).
//
//	"Identities from different networks" therefore means a quorum PER
//	CHAIN: each EVM chain the network onboards carries its own
//	executor set + block-pin RPC. The binary builds one PKHVerifier
//	per chain and routes via did.MultiChainPKHVerifier (Trust
//	Alignment 2; SDK Principle 9).
//
//	The zero value (Enabled=false) is EOA-only: did:key, did:pkh-EOA
//	(ECDSA / EIP-191 / EIP-712), and did:web verify pure-CPU and
//	chain-agnostically; SigAlgoEIP1271 is rejected.
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
// executor's eth_call and to the block-pin RPC when a chain's quorum
// leaves RPCTimeout zero.
const DefaultSCWRPCTimeout = 5 * time.Second

// DefaultSCWConfirmationDepth is the default number of blocks behind
// a chain's head the BlockProvider pins to when ConfirmationDepth is
// zero. 12 blocks is the conventional Ethereum-mainnet finality
// heuristic — deep enough that a pinned block is extremely unlikely
// to be reorged out from under an in-flight verification batch. L2s
// with faster finality may set a smaller value per chain.
const DefaultSCWConfirmationDepth uint64 = 12

// ExecutorEndpoint is one independent Ethereum JSON-RPC backend in a
// chain's EIP-1271 executor quorum. Each executor SHOULD be a distinct
// client implementation on independent infrastructure (e.g., Reth +
// Erigon + Nethermind) so a single compromised or buggy archive node
// cannot poison the transparency log.
type ExecutorEndpoint struct {
	// ID is the operator-declared identifier of this executor
	// (e.g., "reth-us-east-1a"). Non-empty, unique within the
	// chain's quorum, and <= types.MaxExecutorClientIDLen bytes.
	// Flows verbatim into the Web3VerificationReceipt's per-executor
	// attestation.
	ID string `json:"id"`

	// Endpoint is the JSON-RPC URL. https:// required unless the
	// parent SmartContractWallet sets AllowInsecureHTTP (local-dev).
	Endpoint string `json:"endpoint"`
}

// ChainQuorumConfig is the EIP-1271 executor quorum for a single EVM
// chain. Self-contained: its own block-pin RPC + executor set, so a
// Base block is never pinned from a Mainnet node.
type ChainQuorumConfig struct {
	// ChainID is the CAIP-2 / EIP-155 chain identifier (1 = Ethereum
	// mainnet, 8453 = Base, …). Non-zero, unique across the
	// SmartContractWallet.Chains slice. A did:pkh:eip155:<ChainID>
	// routes to this quorum; the SDK PKHVerifier rejects any DID
	// whose chain reference differs (did.ErrChainIDMismatch).
	ChainID uint64 `json:"chain_id"`

	// EthRPCEndpoint is THIS chain's JSON-RPC URL — the head-tracking
	// BlockProvider's pin source. Required. https:// unless
	// AllowInsecureHTTP. Distinct from the executor set: pinning the
	// block and fanning the eth_call are separate roles.
	EthRPCEndpoint string `json:"eth_rpc_endpoint"`

	// Executors is this chain's quorum of independent RPC backends —
	// exactly the executor set handed to the chain's PKHVerifier.
	// Required, with len >= 2, len >= QuorumK, and len <=
	// types.MaxExecutorQuorumClients.
	Executors []ExecutorEndpoint `json:"executors"`

	// QuorumK is the minimum count of executors that MUST agree on the
	// same canonical eth_call result. 2 <= QuorumK <= len(Executors);
	// the SDK rejects QuorumK < 2 (a single executor offers no
	// Byzantine-fault protection).
	QuorumK int `json:"quorum_k"`

	// ConfirmationDepth is the blocks-behind-head this chain pins to.
	// Zero applies DefaultSCWConfirmationDepth (12).
	ConfirmationDepth uint64 `json:"confirmation_depth,omitempty"`
}

// EffectiveConfirmationDepth returns the configured depth or the
// default when unset.
func (c ChainQuorumConfig) EffectiveConfirmationDepth() uint64 {
	if c.ConfirmationDepth == 0 {
		return DefaultSCWConfirmationDepth
	}
	return c.ConfirmationDepth
}

// SmartContractWalletConfig configures multi-chain EIP-1271 K-of-N
// verification. Zero value (Enabled=false) → EOA-only.
type SmartContractWalletConfig struct {
	// Enabled is the master switch. When false (the default), the
	// signature verifier runs EOA-only (chain-agnostic) and
	// SigAlgoEIP1271 entries are rejected.
	Enabled bool `json:"enabled"`

	// Chains is the per-chain executor quorum set — one entry per EVM
	// chain onboarded for SCW signers. Required (>= 1) when Enabled.
	// A did:pkh whose chain is absent here is rejected fail-closed
	// (did.ErrChainNotConfigured) — the network only verifies
	// identities from networks it has explicitly onboarded.
	Chains []ChainQuorumConfig `json:"chains,omitempty"`

	// RPCTimeout caps each executor eth_call and block-pin RPC across
	// all chains. Zero applies DefaultSCWRPCTimeout (5s).
	RPCTimeout time.Duration `json:"rpc_timeout,omitempty"`

	// AllowInsecureHTTP opts in to http:// endpoints (executors AND
	// block-pin) across all chains. Local-dev only; production MUST
	// keep this false (the SDK's HTTP RPC client rejects http://
	// without the matching opt-in).
	AllowInsecureHTTP bool `json:"allow_insecure_http,omitempty"`
}

// EffectiveRPCTimeout returns the configured RPCTimeout or the default.
func (c SmartContractWalletConfig) EffectiveRPCTimeout() time.Duration {
	if c.RPCTimeout <= 0 {
		return DefaultSCWRPCTimeout
	}
	return c.RPCTimeout
}

// validate enforces the per-chain quorum invariants at boot. A
// disabled config is always valid (EOA-only has no quorum needs).
// Mirrors the SDK's PKHVerifierOptions + MultiChainPKHVerifier
// construction checks so misconfiguration fails at boot rather than
// on the first smart-contract-wallet entry.
func (c SmartContractWalletConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if len(c.Chains) == 0 {
		return fmt.Errorf("%w: SmartContractWallet.Chains required when enabled (>= 1 onboarded chain)", ErrInvalidConfig)
	}
	seenChain := make(map[uint64]struct{}, len(c.Chains))
	for ci, chain := range c.Chains {
		if chain.ChainID == 0 {
			return fmt.Errorf("%w: SmartContractWallet.Chains[%d].ChainID required (non-zero)", ErrInvalidConfig, ci)
		}
		if _, dup := seenChain[chain.ChainID]; dup {
			return fmt.Errorf("%w: SmartContractWallet.Chains[%d].ChainID %d duplicated", ErrInvalidConfig, ci, chain.ChainID)
		}
		seenChain[chain.ChainID] = struct{}{}

		if chain.EthRPCEndpoint == "" {
			return fmt.Errorf("%w: SmartContractWallet.Chains[%d] (chain %d) EthRPCEndpoint required (block-pin source)", ErrInvalidConfig, ci, chain.ChainID)
		}
		if err := c.checkEndpoint(chain.EthRPCEndpoint); err != nil {
			return fmt.Errorf("%w: SmartContractWallet.Chains[%d] (chain %d) EthRPCEndpoint: %v", ErrInvalidConfig, ci, chain.ChainID, err)
		}
		if len(chain.Executors) == 0 {
			return fmt.Errorf("%w: SmartContractWallet.Chains[%d] (chain %d) Executors required (>= 2 for K-of-N)", ErrInvalidConfig, ci, chain.ChainID)
		}
		if len(chain.Executors) > sdktypes.MaxExecutorQuorumClients {
			return fmt.Errorf("%w: SmartContractWallet.Chains[%d] (chain %d) Executors length %d exceeds SDK max %d",
				ErrInvalidConfig, ci, chain.ChainID, len(chain.Executors), sdktypes.MaxExecutorQuorumClients)
		}
		if chain.QuorumK < 2 {
			return fmt.Errorf("%w: SmartContractWallet.Chains[%d] (chain %d) QuorumK must be >= 2 (got %d); a single executor offers no Byzantine-fault protection",
				ErrInvalidConfig, ci, chain.ChainID, chain.QuorumK)
		}
		if chain.QuorumK > len(chain.Executors) {
			return fmt.Errorf("%w: SmartContractWallet.Chains[%d] (chain %d) QuorumK %d exceeds executor count %d",
				ErrInvalidConfig, ci, chain.ChainID, chain.QuorumK, len(chain.Executors))
		}
		seenID := make(map[string]struct{}, len(chain.Executors))
		for ei, ex := range chain.Executors {
			if ex.ID == "" {
				return fmt.Errorf("%w: SmartContractWallet.Chains[%d].Executors[%d].ID required", ErrInvalidConfig, ci, ei)
			}
			if len(ex.ID) > sdktypes.MaxExecutorClientIDLen {
				return fmt.Errorf("%w: SmartContractWallet.Chains[%d].Executors[%d].ID exceeds SDK max %d bytes",
					ErrInvalidConfig, ci, ei, sdktypes.MaxExecutorClientIDLen)
			}
			if _, dup := seenID[ex.ID]; dup {
				return fmt.Errorf("%w: SmartContractWallet.Chains[%d].Executors[%d].ID %q duplicated", ErrInvalidConfig, ci, ei, ex.ID)
			}
			seenID[ex.ID] = struct{}{}
			if ex.Endpoint == "" {
				return fmt.Errorf("%w: SmartContractWallet.Chains[%d].Executors[%d].Endpoint required", ErrInvalidConfig, ci, ei)
			}
			if err := c.checkEndpoint(ex.Endpoint); err != nil {
				return fmt.Errorf("%w: SmartContractWallet.Chains[%d].Executors[%d].Endpoint: %v", ErrInvalidConfig, ci, ei, err)
			}
		}
	}
	return nil
}

// checkEndpoint rejects http:// endpoints unless AllowInsecureHTTP.
func (c SmartContractWalletConfig) checkEndpoint(endpoint string) error {
	if strings.HasPrefix(strings.ToLower(endpoint), "http://") && !c.AllowInsecureHTTP {
		return fmt.Errorf("http:// endpoint but AllowInsecureHTTP is false")
	}
	return nil
}
