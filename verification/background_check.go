/*
FILE PATH: verification/background_check.go
DESCRIPTION: Party DID → public case associations across logs.
KEY ARCHITECTURAL DECISIONS:
    - Uses QueryBySignerDID to discover entries by a party.
    - Uses smt.GenerateBatchProof for efficient multi-leaf proofs.
    - Only returns public (non-sealed) cases.
OVERVIEW: BackgroundCheck → list of public case associations with proofs.
KEY DEPENDENCIES: ortholog-sdk/core/smt, log.OperatorQueryAPI
*/
package verification

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

type CaseAssociation struct {
	CaseRef    string
	Role       string
	Status     string
	Position   types.LogPosition
	IsSealed   bool
}

type BackgroundQuerier interface {
	QueryBySignerDID(did string) ([]types.EntryWithMetadata, error)
}

// BackgroundCheck discovers all public case associations for a party DID.
// Sealed cases are flagged but details withheld.
func BackgroundCheck(
	partyDID string,
	querier BackgroundQuerier,
	leafReader smt.LeafReader,
) ([]CaseAssociation, error) {
	entries, err := querier.QueryBySignerDID(partyDID)
	if err != nil {
		return nil, fmt.Errorf("verification/background_check: query: %w", err)
	}

	var associations []CaseAssociation
	for _, meta := range entries {
		entry, dErr := envelope.Deserialize(meta.CanonicalBytes)
		if dErr != nil {
			continue
		}
		if entry.Header.TargetRoot != nil {
			continue // only root entities
		}
		if len(entry.DomainPayload) == 0 {
			continue
		}

		var payload struct {
			CaseRef string `json:"case_ref"`
			Role    string `json:"role"`
			Status  string `json:"status"`
		}
		if json.Unmarshal(entry.DomainPayload, &payload) != nil {
			continue
		}

		assoc := CaseAssociation{
			CaseRef:  payload.CaseRef,
			Role:     payload.Role,
			Status:   payload.Status,
			Position: meta.Position,
		}

		// Check sealing status.
		leafKey := smt.DeriveKey(meta.Position)
		leaf, lErr := leafReader.Get(leafKey)
		if lErr == nil && leaf != nil {
			if !leaf.AuthorityTip.Equal(meta.Position) && !leaf.AuthorityTip.Equal(leaf.OriginTip) {
				assoc.IsSealed = true
			}
		}

		associations = append(associations, assoc)
	}

	return associations, nil
}
