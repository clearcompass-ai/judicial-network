// FILE PATH: api/config/scw_test.go
//
// Tests for the EIP-1271 smart-contract-wallet quorum config
// validation. The zero value (disabled) must always pass; an
// enabled config must enforce the SDK's PKHVerifierOptions
// invariants (ChainID, >= 2 executors, K in [2, N], unique
// non-empty IDs, https-or-opt-in) at boot.
package config

import (
	"errors"
	"strings"
	"testing"
)

func enabledSCW() SmartContractWalletConfig {
	return SmartContractWalletConfig{
		Enabled: true,
		ChainID: 1,
		Executors: []ExecutorEndpoint{
			{ID: "reth", Endpoint: "https://reth.example"},
			{ID: "erigon", Endpoint: "https://erigon.example"},
		},
		QuorumK: 2,
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
	// The zero value (and any disabled config, even with garbage
	// fields) is valid — EOA-only verification has no quorum needs.
	if err := (SmartContractWalletConfig{}).validate(); err != nil {
		t.Fatalf("zero-value SCW config must be valid: %v", err)
	}
	garbage := SmartContractWalletConfig{Enabled: false, QuorumK: -5, Executors: nil}
	if err := garbage.validate(); err != nil {
		t.Fatalf("disabled SCW config must be valid regardless of other fields: %v", err)
	}
}

func TestSCWConfig_EnabledHappyPath(t *testing.T) {
	if err := enabledSCW().validate(); err != nil {
		t.Fatalf("valid enabled SCW config rejected: %v", err)
	}
}

func TestSCWConfig_RejectsZeroChainID(t *testing.T) {
	c := enabledSCW()
	c.ChainID = 0
	expectSCWInvalid(t, c, "ChainID required")
}

func TestSCWConfig_RejectsNoExecutors(t *testing.T) {
	c := enabledSCW()
	c.Executors = nil
	expectSCWInvalid(t, c, "Executors required")
}

func TestSCWConfig_RejectsQuorumKBelowTwo(t *testing.T) {
	c := enabledSCW()
	c.QuorumK = 1
	expectSCWInvalid(t, c, "QuorumK must be >= 2")
}

func TestSCWConfig_RejectsQuorumKAboveExecutorCount(t *testing.T) {
	c := enabledSCW()
	c.QuorumK = 3 // only 2 executors
	expectSCWInvalid(t, c, "exceeds executor count")
}

func TestSCWConfig_RejectsDuplicateExecutorID(t *testing.T) {
	c := enabledSCW()
	c.Executors[1].ID = "reth" // same as Executors[0]
	expectSCWInvalid(t, c, "duplicated")
}

func TestSCWConfig_RejectsEmptyExecutorID(t *testing.T) {
	c := enabledSCW()
	c.Executors[0].ID = ""
	expectSCWInvalid(t, c, "ID required")
}

func TestSCWConfig_RejectsEmptyExecutorEndpoint(t *testing.T) {
	c := enabledSCW()
	c.Executors[1].Endpoint = ""
	expectSCWInvalid(t, c, "Endpoint required")
}

func TestSCWConfig_RejectsInsecureEndpointWithoutOptIn(t *testing.T) {
	c := enabledSCW()
	c.Executors[0].Endpoint = "http://reth.local:8545"
	expectSCWInvalid(t, c, "AllowInsecureHTTP is false")
}

func TestSCWConfig_AllowsInsecureEndpointWithOptIn(t *testing.T) {
	c := enabledSCW()
	c.AllowInsecureHTTP = true
	c.Executors[0].Endpoint = "http://reth.local:8545"
	if err := c.validate(); err != nil {
		t.Fatalf("http endpoint with AllowInsecureHTTP=true must validate: %v", err)
	}
}

func TestSCWConfig_Defaults(t *testing.T) {
	c := SmartContractWalletConfig{}
	if c.EffectiveRPCTimeout() != DefaultSCWRPCTimeout {
		t.Errorf("EffectiveRPCTimeout = %v, want %v", c.EffectiveRPCTimeout(), DefaultSCWRPCTimeout)
	}
	if c.EffectiveConfirmationDepth() != DefaultSCWConfirmationDepth {
		t.Errorf("EffectiveConfirmationDepth = %v, want %v", c.EffectiveConfirmationDepth(), DefaultSCWConfirmationDepth)
	}
}

// Validate (the top-level Operational validator) must surface SCW
// errors so a misconfigured quorum aborts boot.
func TestOperationalValidate_SurfacesSCWError(t *testing.T) {
	cfg := validBase(t)
	cfg.SmartContractWallet = SmartContractWalletConfig{Enabled: true} // missing everything
	expectInvalid(t, cfg, "ChainID required")
}
