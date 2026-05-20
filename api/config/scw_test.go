// FILE PATH: api/config/scw_test.go
//
// Tests for the multi-chain EIP-1271 quorum config validation. The
// zero value (disabled) must always pass; an enabled config must
// enforce per-chain PKHVerifierOptions invariants (>= 1 chain, each
// chain: non-zero unique ChainID, block-pin endpoint, >= 2 executors,
// K in [2, N], unique non-empty executor IDs, https-or-opt-in) at
// boot.
package config

import (
	"errors"
	"strings"
	"testing"
)

func enabledChain(id uint64) ChainQuorumConfig {
	return ChainQuorumConfig{
		ChainID:        id,
		EthRPCEndpoint: "https://pin.example",
		Executors: []ExecutorEndpoint{
			{ID: "reth", Endpoint: "https://reth.example"},
			{ID: "erigon", Endpoint: "https://erigon.example"},
		},
		QuorumK: 2,
	}
}

func enabledSCW() SmartContractWalletConfig {
	return SmartContractWalletConfig{
		Enabled: true,
		Chains:  []ChainQuorumConfig{enabledChain(1), enabledChain(8453)},
	}
}

func expectSCWInvalid(t *testing.T, c SmartContractWalletConfig, mustContain string) {
	t.Helper()
	err := c.validate()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", mustContain)
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error should wrap ErrInvalidConfig: %v", err)
	}
	if !strings.Contains(err.Error(), mustContain) {
		t.Errorf("error %q should contain %q", err.Error(), mustContain)
	}
}

func TestSCWConfig_DisabledIsAlwaysValid(t *testing.T) {
	if err := (SmartContractWalletConfig{}).validate(); err != nil {
		t.Fatalf("zero-value SCW config must be valid: %v", err)
	}
	garbage := SmartContractWalletConfig{Enabled: false, Chains: []ChainQuorumConfig{{ChainID: 0, QuorumK: -5}}}
	if err := garbage.validate(); err != nil {
		t.Fatalf("disabled SCW config must be valid regardless of other fields: %v", err)
	}
}

func TestSCWConfig_EnabledHappyPath_MultiChain(t *testing.T) {
	if err := enabledSCW().validate(); err != nil {
		t.Fatalf("valid multi-chain SCW config rejected: %v", err)
	}
}

func TestSCWConfig_RejectsNoChains(t *testing.T) {
	c := SmartContractWalletConfig{Enabled: true}
	expectSCWInvalid(t, c, "Chains required")
}

func TestSCWConfig_RejectsZeroChainID(t *testing.T) {
	c := enabledSCW()
	c.Chains[0].ChainID = 0
	expectSCWInvalid(t, c, "ChainID required")
}

func TestSCWConfig_RejectsDuplicateChainID(t *testing.T) {
	c := enabledSCW()
	c.Chains[1].ChainID = 1 // same as Chains[0]
	expectSCWInvalid(t, c, "duplicated")
}

func TestSCWConfig_RejectsMissingBlockPinEndpoint(t *testing.T) {
	c := enabledSCW()
	c.Chains[0].EthRPCEndpoint = ""
	expectSCWInvalid(t, c, "EthRPCEndpoint required")
}

func TestSCWConfig_RejectsNoExecutors(t *testing.T) {
	c := enabledSCW()
	c.Chains[0].Executors = nil
	expectSCWInvalid(t, c, "Executors required")
}

func TestSCWConfig_RejectsQuorumKBelowTwo(t *testing.T) {
	c := enabledSCW()
	c.Chains[0].QuorumK = 1
	expectSCWInvalid(t, c, "QuorumK must be >= 2")
}

func TestSCWConfig_RejectsQuorumKAboveExecutorCount(t *testing.T) {
	c := enabledSCW()
	c.Chains[0].QuorumK = 3 // only 2 executors
	expectSCWInvalid(t, c, "exceeds executor count")
}

func TestSCWConfig_RejectsDuplicateExecutorID(t *testing.T) {
	c := enabledSCW()
	c.Chains[0].Executors[1].ID = "reth" // same as Executors[0]
	expectSCWInvalid(t, c, "duplicated")
}

func TestSCWConfig_RejectsEmptyExecutorID(t *testing.T) {
	c := enabledSCW()
	c.Chains[0].Executors[0].ID = ""
	expectSCWInvalid(t, c, "ID required")
}

func TestSCWConfig_RejectsEmptyExecutorEndpoint(t *testing.T) {
	c := enabledSCW()
	c.Chains[0].Executors[1].Endpoint = ""
	expectSCWInvalid(t, c, "Endpoint required")
}

func TestSCWConfig_RejectsInsecureEndpointWithoutOptIn(t *testing.T) {
	c := enabledSCW()
	c.Chains[0].Executors[0].Endpoint = "http://reth.local:8545"
	expectSCWInvalid(t, c, "AllowInsecureHTTP is false")
}

func TestSCWConfig_RejectsInsecureBlockPinWithoutOptIn(t *testing.T) {
	c := enabledSCW()
	c.Chains[0].EthRPCEndpoint = "http://pin.local:8545"
	expectSCWInvalid(t, c, "AllowInsecureHTTP is false")
}

func TestSCWConfig_AllowsInsecureWithOptIn(t *testing.T) {
	c := enabledSCW()
	c.AllowInsecureHTTP = true
	c.Chains[0].EthRPCEndpoint = "http://pin.local:8545"
	c.Chains[0].Executors[0].Endpoint = "http://reth.local:8545"
	if err := c.validate(); err != nil {
		t.Fatalf("http endpoints with AllowInsecureHTTP=true must validate: %v", err)
	}
}

func TestSCWConfig_Defaults(t *testing.T) {
	c := SmartContractWalletConfig{}
	if c.EffectiveRPCTimeout() != DefaultSCWRPCTimeout {
		t.Errorf("EffectiveRPCTimeout = %v, want %v", c.EffectiveRPCTimeout(), DefaultSCWRPCTimeout)
	}
	chain := ChainQuorumConfig{}
	if chain.EffectiveConfirmationDepth() != DefaultSCWConfirmationDepth {
		t.Errorf("EffectiveConfirmationDepth = %v, want %v", chain.EffectiveConfirmationDepth(), DefaultSCWConfirmationDepth)
	}
}

// Validate (the top-level Operational validator) must surface SCW
// errors so a misconfigured quorum aborts boot.
func TestOperationalValidate_SurfacesSCWError(t *testing.T) {
	cfg := validBase(t)
	cfg.SmartContractWallet = SmartContractWalletConfig{Enabled: true} // no chains
	expectInvalid(t, cfg, "Chains required")
}
