/*
FILE PATH: parties/roster.go
DESCRIPTION: Case party roster management. Links parties to cases via
    cross-log commentary entries. Query helpers for party discovery.
KEY ARCHITECTURAL DECISIONS:
    - BuildCommentary on cases log referencing party binding position on parties log.
    - QueryByTargetRoot on parties log to find bindings for a case.
    - No SMT mutation — commentary entries are zero-impact.
OVERVIEW: LinkPartyToCase → commentary. ListCaseParties / FindPartyByDID → queries.
KEY DEPENDENCIES: ortholog-sdk/builder, ortholog-sdk/log
*/
package parties

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// PartiesQuerier discovers party binding entries.
// Satisfied by log.OperatorQueryAPI (structural typing).
type PartiesQuerier interface {
	QueryBySignerDID(did string) ([]types.EntryWithMetadata, error)
	QueryByTargetRoot(pos types.LogPosition) ([]types.EntryWithMetadata, error)
}

// PartyLink represents a discovered party-case association.
type PartyLink struct {
	BindingPos types.LogPosition
	PartyDID   string
	Role       string
	Status     string
	CaseRef    string
	IsSealed   bool
}

// LinkPartyCaseConfig configures a cross-log party-case link.
type LinkPartyCaseConfig struct {
	Destination string // DID of target exchange. Required.
	SignerDID    string            // Court clerk signing the commentary
	CaseRootPos  types.LogPosition // Case root on cases log
	BindingPos   types.LogPosition // Party binding on parties log
	PartyDID     string
	PartiesLogDID string           // DID of the parties log
	Role         string
	EventTime    int64
}

// LinkPartyToCase publishes a commentary entry on the cases log that
// references a party binding on the parties log. Cross-log link.
func LinkPartyToCase(cfg LinkPartyCaseConfig) (*envelope.Entry, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("parties/roster: empty signer DID")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"link_type":       "party_case_association",
		"party_did":       cfg.PartyDID,
		"role":            cfg.Role,
		"binding_log_did": cfg.PartiesLogDID,
		"binding_seq":     cfg.BindingPos.Sequence,
	})

	return builder.BuildCommentary(builder.CommentaryParams{
		Destination: cfg.Destination,
		SignerDID: cfg.SignerDID,
		Payload:   payload,
		EventTime: cfg.EventTime,
	})
}

// ListCaseParties queries the parties log for all bindings associated
// with a case reference (docket number). Returns discovered party links.
func ListCaseParties(
	signerDID string,
	querier PartiesQuerier,
) ([]PartyLink, error) {
	entries, err := querier.QueryBySignerDID(signerDID)
	if err != nil {
		return nil, fmt.Errorf("parties/roster: query: %w", err)
	}

	var links []PartyLink
	for _, meta := range entries {
		entry, dErr := envelope.Deserialize(meta.CanonicalBytes)
		if dErr != nil || len(entry.DomainPayload) == 0 {
			continue
		}

		// Only root entities (bindings, not amendments).
		if entry.Header.TargetRoot != nil {
			continue
		}

		var payload struct {
			PartyDID  string `json:"party_did"`
			VendorDID string `json:"vendor_did"`
			CaseRef   string `json:"case_ref"`
			Role      string `json:"role"`
			Status    string `json:"status"`
		}
		if json.Unmarshal(entry.DomainPayload, &payload) != nil {
			continue
		}

		link := PartyLink{
			BindingPos: meta.Position,
			PartyDID:   payload.PartyDID,
			Role:       payload.Role,
			Status:     payload.Status,
			CaseRef:    payload.CaseRef,
		}
		if payload.VendorDID != "" {
			link.PartyDID = payload.VendorDID
			link.IsSealed = true
		}
		links = append(links, link)
	}

	return links, nil
}

// FindPartyByDID searches for a party binding by DID.
func FindPartyByDID(
	partyDID string,
	querier PartiesQuerier,
) (*PartyLink, error) {
	entries, err := querier.QueryBySignerDID(partyDID)
	if err != nil {
		return nil, fmt.Errorf("parties/roster: query by DID: %w", err)
	}

	for _, meta := range entries {
		entry, dErr := envelope.Deserialize(meta.CanonicalBytes)
		if dErr != nil || entry.Header.TargetRoot != nil {
			continue
		}
		if len(entry.DomainPayload) == 0 {
			continue
		}

		var payload struct {
			PartyDID string `json:"party_did"`
			CaseRef  string `json:"case_ref"`
			Role     string `json:"role"`
			Status   string `json:"status"`
		}
		if json.Unmarshal(entry.DomainPayload, &payload) != nil {
			continue
		}

		return &PartyLink{
			BindingPos: meta.Position,
			PartyDID:   payload.PartyDID,
			Role:       payload.Role,
			Status:     payload.Status,
			CaseRef:    payload.CaseRef,
		}, nil
	}

	return nil, fmt.Errorf("parties/roster: party %s not found", partyDID)
}
