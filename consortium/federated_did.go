package consortium

import (
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"

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
// translation transparently.
func (fr *FederatedResolver) Resolve(didStr string) (*did.DIDDocument, error) {
	return fr.resolver.Resolve(didStr)
}

// BuildCrossCourtProof constructs a compound proof that an entry on
// one court's log is verifiable from another court's perspective.
func BuildCrossCourtProof(
	sourceRef types.LogPosition,
	anchorRef types.LogPosition,
	fetcher types.EntryFetcher,
	sourceProver verifier.MerkleProver,
	localProver verifier.MerkleProver,
	sourceHead types.CosignedTreeHead,
	localHead types.CosignedTreeHead,
) (*types.CrossLogProof, error) {
	return verifier.BuildCrossLogProof(
		sourceRef, anchorRef, fetcher,
		sourceProver, localProver,
		sourceHead, localHead,
	)
}

// VerifyCrossCourtProof verifies a compound proof across courts.
func VerifyCrossCourtProof(
	proof types.CrossLogProof,
	sourceWitnessKeys []types.WitnessPublicKey,
	sourceQuorumK int,
	blsVerifier signatures.BLSVerifier,
) error {
	return verifier.VerifyCrossLogProof(proof, sourceWitnessKeys, sourceQuorumK, blsVerifier, topology.ExtractAnchorPayload)
}
