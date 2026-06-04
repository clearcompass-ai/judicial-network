package consortium

import (
	"context"

	"github.com/baseproof/baseproof/did"

	judicialdid "github.com/clearcompass-ai/judicial-network/did"
)

// FederatedResolver resolves DIDs across consortium member courts.
type FederatedResolver struct {
	resolver *did.VendorDIDResolver
}

// NewFederatedResolver creates a resolver that handles all judicial
// DID methods (court, jnet, ccr) plus standard did:web resolution.
func NewFederatedResolver(baseResolver did.DIDResolver) *FederatedResolver {
	return &FederatedResolver{
		resolver: did.NewVendorDIDResolver(baseResolver, judicialdid.AllMappings()),
	}
}

// Resolve resolves a DID to its document, handling vendor DID
// translation transparently. ctx bounds the resolver RPC.
func (fr *FederatedResolver) Resolve(ctx context.Context, didStr string) (*did.DIDDocument, error) {
	return fr.resolver.Resolve(ctx, didStr)
}

// NOTE: cross-court proof build/verify are NOT wrapped here. They are
// domain-agnostic SDK capabilities — callers invoke them directly:
//   - build:  verifier.BuildCrossLogProof(...)
//   - verify: anchor.VerifyCrossLog(proof, sourceSet, trust)
// (the former BuildCrossCourtProof/VerifyCrossCourtProof pass-throughs added a
// judicial name but zero judicial logic, so they were removed — JN#110.)
