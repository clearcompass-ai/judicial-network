/*
FILE PATH: crosslog/witness_sets.go

DESCRIPTION:

	BuildWitnessSets populates Dependencies.WitnessSets — the per-source-log
	*cosign.WitnessKeySet map that every cross-log verification path reads
	(VerifyCrossLogProof, VerifyCosignedAnchor). Each configured source/peer
	log's witness DIDs are resolved to secp256k1 public keys (witness.KeysFromDIDs)
	and bound, with the log's K-of-N quorum and the network-wide cosign
	NetworkID, into one keyset.

	ECDSA-only (NewECDSAWitnessKeySet): JN's federation witnesses sign with
	secp256k1, matching the protocol curve. BLS witness sets are a separate
	plane (not wired here).
*/
package crosslog

import (
	"fmt"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/witness"

	"github.com/clearcompass-ai/judicial-network/api/config"
)

// BuildWitnessSets resolves each configured source/peer log's witness DIDs
// into a *cosign.WitnessKeySet keyed by log DID. All sets bind to the
// network-wide networkID. Returns an error on a duplicate or empty log DID,
// an unresolvable witness DID, or an invalid quorum (the SDK's keyset
// constructor enforces 1 <= K <= N, unique non-empty keys, non-zero
// NetworkID). An empty sets slice yields an empty (non-nil) map.
func BuildWitnessSets(sets []config.WitnessSetConfig, networkID cosign.NetworkID) (map[string]*cosign.WitnessKeySet, error) {
	out := make(map[string]*cosign.WitnessKeySet, len(sets))
	for i, s := range sets {
		if s.LogDID == "" {
			return nil, fmt.Errorf("crosslog: witness set[%d]: log_did required", i)
		}
		if _, dup := out[s.LogDID]; dup {
			return nil, fmt.Errorf("crosslog: duplicate witness set for %q", s.LogDID)
		}
		keys, err := witness.KeysFromDIDs(s.WitnessDIDs)
		if err != nil {
			return nil, fmt.Errorf("crosslog: %q witness keys: %w", s.LogDID, err)
		}
		ks, err := cosign.NewECDSAWitnessKeySet(keys, networkID, s.QuorumK)
		if err != nil {
			return nil, fmt.Errorf("crosslog: %q keyset: %w", s.LogDID, err)
		}
		out[s.LogDID] = ks
	}
	return out, nil
}
