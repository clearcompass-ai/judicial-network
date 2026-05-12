package consortium

import (
	"context"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/did"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"

	judicialdid "github.com/clearcompass-ai/judicial-network/did"
	"github.com/clearcompass-ai/judicial-network/topology"
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

// BuildCrossCourtProof constructs a compound proof that an entry on
// one court's log is verifiable from another court's perspective.
// ctx threads into the fetcher / prover RPCs.
func BuildCrossCourtProof(
	ctx context.Context,
	sourceRef types.LogPosition,
	anchorRef types.LogPosition,
	fetcher types.EntryFetcher,
	sourceProver verifier.MerkleProver,
	localProver verifier.MerkleProver,
	sourceHead types.CosignedTreeHead,
	localHead types.CosignedTreeHead,
) (*types.CrossLogProof, error) {
	return verifier.BuildCrossLogProof(ctx,
		sourceRef, anchorRef, fetcher,
		sourceProver, localProver,
		sourceHead, localHead,
	)
}

// VerifyCrossCourtProof verifies a compound proof across courts.
// v0.3.0: the (keys, K, networkID, blsVerifier) parameter group is
// encapsulated into a single *cosign.WitnessKeySet representing the
// SOURCE network's witness topology, preventing the class of bug
// where K and the key set drift out of sync for a given log.
func VerifyCrossCourtProof(
	proof types.CrossLogProof,
	sourceSet *cosign.WitnessKeySet,
) error {
	return verifier.VerifyCrossLogProof(proof, sourceSet, topology.ExtractAnchorPayload)
}
