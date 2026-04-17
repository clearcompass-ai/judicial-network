/*
FILE PATH: consortium/federated_did.go

DESCRIPTION:
    Cross-court DID resolution within a consortium. Uses the SDK's
    VendorDIDResolver (guide §17.2) and cross-log proof verification
    (guide §24.1) to resolve DIDs across member courts.

KEY DEPENDENCIES:
    - ortholog-sdk/did: VendorDIDResolver, VendorMapping (guide §17.2)
    - ortholog-sdk/verifier: BuildCrossLogProof, VerifyCrossLogProof
      (guide §24.1)
    - judicial-network/did: AllMappings
*/
package consortium

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"

	judicialdid "github.com/clearcompass-ai/judicial-network/did"
)

// FederatedResolver resolves DIDs across consortium member courts.
// It wraps a VendorDIDResolver with the judicial network's vendor
// mappings and adds cross-log proof construction for inter-court
// verification.
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

// CrossLogProofParams configures a cross-log proof request between
// two member courts.
type CrossLogProofParams struct {
	// SourceLogDID is the log where the entry lives.
	SourceLogDID string

	// SourceEntryPos is the entry's position on the source log.
	SourceEntryPos uint64

	// TargetLogDID is the log from whose perspective the proof is
	// being constructed (the verifier's log).
	TargetLogDID string

	// AnchorLogDID is the shared anchor log that both courts anchor to.
	// For TN consortium: did:web:courts.tn.gov:anchor
	AnchorLogDID string

	// Fetcher provides access to log entries and tree heads.
	Fetcher verifier.CrossLogFetcher
}

// BuildCrossCourtProof constructs a compound proof that an entry on
// one court's log is verifiable from another court's perspective,
// through the shared consortium anchor.
func BuildCrossCourtProof(params CrossLogProofParams) (*verifier.CrossLogProofResult, error) {
	if params.SourceLogDID == "" || params.TargetLogDID == "" {
		return nil, fmt.Errorf("consortium/federated_did: source and target log DIDs required")
	}
	if params.AnchorLogDID == "" {
		return nil, fmt.Errorf("consortium/federated_did: anchor log DID required")
	}

	return verifier.BuildCrossLogProof(verifier.CrossLogProofParams{
		SourceLogDID:   params.SourceLogDID,
		SourceEntryPos: params.SourceEntryPos,
		TargetLogDID:   params.TargetLogDID,
		AnchorLogDID:   params.AnchorLogDID,
		Fetcher:        params.Fetcher,
	})
}

// VerifyCrossCourtProof verifies a compound proof that an entry on
// one court's log is consistent with another court's view through
// the shared anchor.
func VerifyCrossCourtProof(proof *verifier.CrossLogProofResult, fetcher verifier.CrossLogFetcher) error {
	return verifier.VerifyCrossLogProof(proof, fetcher)
}
