/*
FILE PATH: crosslog/anchor.go

DESCRIPTION:

	The JN's cross-log verification entry point. It consumes the SDK-owned
	cosigned anchor (attesta/anchor, anchor_type="cosigned_tree_head_v1") and
	proves a foreign entry's inclusion against it — entirely offline (no
	callback to the source log, which may by then be offline / equivocating).

	The anchor format + its verification live ONCE in the SDK (attesta/anchor):
	the JN no longer mirrors the payload struct or re-implements the quorum
	check. This is the self-contained model — trust flows from the embedded
	K-of-N quorum recomputed locally (anchor.VerifyCosignedAnchor), not from a
	destination-log commitment — which is strictly stronger than the legacy
	tree_head_ref binding and is Alignment 6 ("Parse, Don't Validate").
*/
package crosslog

import (
	"fmt"

	"github.com/clearcompass-ai/attesta/anchor"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/types"
)

// VerifyCrossLog verifies a cross-log proof in the self-contained model:
//
//  1. deserialize the anchor entry and recompute the embedded source head's
//     K-of-N witness quorum OFFLINE against sourceSet (anchor.VerifyCosignedAnchor);
//  2. prove the cited source entry's inclusion against that VERIFIED head's
//     RootHash + TreeSize (anchor.VerifiedAnchor.VerifyInclusion).
//
// sourceSet is the source log's witness keyset (Dependencies.WitnessSets,
// resolved from the network bootstrap). Trust comes from the recomputed quorum,
// never from the anchor's publisher or a destination-log commitment.
func VerifyCrossLog(proof types.CrossLogProof, sourceSet *cosign.WitnessKeySet) error {
	anchorEntry, err := envelope.Deserialize(proof.AnchorEntryCanonical)
	if err != nil {
		return fmt.Errorf("crosslog: deserialize anchor entry: %w", err)
	}
	va, err := anchor.VerifyCosignedAnchor(anchorEntry.DomainPayload, sourceSet)
	if err != nil {
		return fmt.Errorf("crosslog: %w", err)
	}
	if err := va.VerifyInclusion(proof.SourceInclusion, proof.SourceEntryHash); err != nil {
		return fmt.Errorf("crosslog: %w", err)
	}
	return nil
}
