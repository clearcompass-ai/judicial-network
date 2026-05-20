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

func TestBuildSignatureVerifier_EOAOnly(t *testing.T) {
	cfg := config.Operational{
		EthRPCEndpoint: "https://rpc.example",
		// SmartContractWallet zero-value → EOA-only.
	}
	v, err := buildSignatureVerifier(cfg, stubResolver{})
	if err != nil {
		t.Fatalf("buildSignatureVerifier (EOA): %v", err)
	}
	if v == nil {
		t.Fatal("verifier must be non-nil")
	}
	// The returned registry must satisfy both SDK verifier interfaces
	// so the Path C composite can collect receipts.
	reg, ok := v.(*did.VerifierRegistry)
	if !ok {
		t.Fatalf("verifier is %T, want *did.VerifierRegistry", v)
	}
	var _ attestation.SignatureVerifier = reg
	var _ attestation.SignatureVerifierWithReceipt = reg
	methods := reg.RegisteredMethods()
	wantMethods := map[string]bool{"pkh": false, "key": false, "web": false}
	for _, m := range methods {
		if _, ok := wantMethods[m]; ok {
			wantMethods[m] = true
		}
	}
	for m, found := range wantMethods {
		if !found {
			t.Errorf("registry missing method %q", m)
		}
	}
}

func TestBuildSignatureVerifier_NilResolver(t *testing.T) {
	_, err := buildSignatureVerifier(config.Operational{EthRPCEndpoint: "https://rpc.example"}, nil)
	if err == nil {
		t.Fatal("nil resolver MUST error")
	}
}

func TestBuildSignatureVerifier_EIP1271Quorum(t *testing.T) {
	cfg := config.Operational{
		EthRPCEndpoint: "https://primary.example",
		SmartContractWallet: config.SmartContractWalletConfig{
			Enabled: true,
			ChainID: 1,
			Executors: []config.ExecutorEndpoint{
				{ID: "reth", Endpoint: "https://reth.example"},
				{ID: "erigon", Endpoint: "https://erigon.example"},
			},
			QuorumK:           2,
			ConfirmationDepth: 12,
		},
	}
	v, err := buildSignatureVerifier(cfg, stubResolver{})
	if err != nil {
		t.Fatalf("buildSignatureVerifier (EIP-1271): %v", err)
	}
	if v == nil {
		t.Fatal("verifier must be non-nil")
	}
}

func TestBuildPKHVerifierOptions_ExactExecutorSet(t *testing.T) {
	cfg := config.Operational{
		EthRPCEndpoint: "https://primary.example",
		SmartContractWallet: config.SmartContractWalletConfig{
			Enabled: true,
			ChainID: 1,
			Executors: []config.ExecutorEndpoint{
				{ID: "reth", Endpoint: "https://reth.example"},
				{ID: "erigon", Endpoint: "https://erigon.example"},
			},
			QuorumK: 2,
		},
	}
	opts, err := buildPKHVerifierOptions(cfg)
	if err != nil {
		t.Fatalf("buildPKHVerifierOptions: %v", err)
	}
	// The executor set is exactly the operator-declared list; the
	// EthRPCEndpoint is the block-pin source, not an executor.
	if len(opts.Executors) != 2 {
		t.Fatalf("executor count = %d, want 2 (exactly scw.Executors)", len(opts.Executors))
	}
	if opts.Executors[0].ID != "reth" || opts.Executors[1].ID != "erigon" {
		t.Errorf("executor IDs = [%q %q], want [reth erigon]", opts.Executors[0].ID, opts.Executors[1].ID)
	}
	if opts.QuorumK != 2 {
		t.Errorf("QuorumK = %d, want 2", opts.QuorumK)
	}
	if opts.BlockProvider == nil {
		t.Error("BlockProvider must be set for EIP-1271 mode")
	}
}

func TestBuildPKHVerifierOptions_EOAReturnsZero(t *testing.T) {
	cfg := config.Operational{EthRPCEndpoint: "https://rpc.example"}
	opts, err := buildPKHVerifierOptions(cfg)
	if err != nil {
		t.Fatalf("buildPKHVerifierOptions (EOA): %v", err)
	}
	if len(opts.Executors) != 0 || opts.BlockProvider != nil || opts.ChainID != 0 {
		t.Errorf("EOA mode MUST yield the zero PKHVerifierOptions; got %+v", opts)
	}
}
