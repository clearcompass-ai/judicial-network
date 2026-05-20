package main

import (
	"context"
	"testing"

	"github.com/clearcompass-ai/attesta/attestation"
	"github.com/clearcompass-ai/attesta/did"

	"github.com/clearcompass-ai/judicial-network/api/config"
)

// stubResolver is a non-nil DID resolver for verifier construction
// tests. It is never actually consulted (the tests don't drive
// did:web entries through the verifier).
type stubResolver struct{}

func (stubResolver) Resolve(context.Context, string) (*did.DIDDocument, error) {
	return nil, context.Canceled
}

func multiChainSCW() config.SmartContractWalletConfig {
	return config.SmartContractWalletConfig{
		Enabled: true,
		Chains: []config.ChainQuorumConfig{
			{
				ChainID:        1,
				EthRPCEndpoint: "https://pin1.example",
				Executors: []config.ExecutorEndpoint{
					{ID: "reth", Endpoint: "https://reth1.example"},
					{ID: "erigon", Endpoint: "https://erigon1.example"},
				},
				QuorumK: 2,
			},
			{
				ChainID:        8453,
				EthRPCEndpoint: "https://pin8453.example",
				Executors: []config.ExecutorEndpoint{
					{ID: "reth", Endpoint: "https://reth8453.example"},
					{ID: "nethermind", Endpoint: "https://neth8453.example"},
				},
				QuorumK: 2,
			},
		},
	}
}

func TestBuildSignatureVerifier_EOAOnly(t *testing.T) {
	cfg := config.Operational{} // SCW disabled → EOA-only
	v, err := buildSignatureVerifier(cfg, stubResolver{})
	if err != nil {
		t.Fatalf("buildSignatureVerifier (EOA): %v", err)
	}
	reg, ok := v.(*did.VerifierRegistry)
	if !ok {
		t.Fatalf("verifier is %T, want *did.VerifierRegistry", v)
	}
	var _ attestation.SignatureVerifier = reg
	var _ attestation.SignatureVerifierWithReceipt = reg
	for _, m := range []string{"pkh", "key", "web"} {
		if !hasMethod(reg, m) {
			t.Errorf("registry missing method %q", m)
		}
	}
}

func TestBuildSignatureVerifier_NilResolver(t *testing.T) {
	_, err := buildSignatureVerifier(config.Operational{}, nil)
	if err == nil {
		t.Fatal("nil resolver MUST error")
	}
}

func TestBuildSignatureVerifier_MultiChain(t *testing.T) {
	cfg := config.Operational{SmartContractWallet: multiChainSCW()}
	v, err := buildSignatureVerifier(cfg, stubResolver{})
	if err != nil {
		t.Fatalf("buildSignatureVerifier (multi-chain): %v", err)
	}
	if v == nil {
		t.Fatal("verifier must be non-nil")
	}
}

func TestBuildPKHVerifier_EOAOnlyType(t *testing.T) {
	v, err := buildPKHVerifier(config.SmartContractWalletConfig{})
	if err != nil {
		t.Fatalf("buildPKHVerifier (EOA): %v", err)
	}
	if _, ok := v.(*did.PKHVerifier); !ok {
		t.Errorf("EOA-only mode MUST yield *did.PKHVerifier, got %T", v)
	}
}

func TestBuildPKHVerifier_MultiChainType(t *testing.T) {
	v, err := buildPKHVerifier(multiChainSCW())
	if err != nil {
		t.Fatalf("buildPKHVerifier (multi-chain): %v", err)
	}
	mc, ok := v.(*did.MultiChainPKHVerifier)
	if !ok {
		t.Fatalf("multi-chain mode MUST yield *did.MultiChainPKHVerifier, got %T", v)
	}
	if len(mc.Chains()) != 2 {
		t.Errorf("router configured for %d chains, want 2", len(mc.Chains()))
	}
}

func hasMethod(reg *did.VerifierRegistry, method string) bool {
	for _, m := range reg.RegisteredMethods() {
		if m == method {
			return true
		}
	}
	return false
}
