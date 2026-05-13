/*
FILE PATH: parties/roster.go

DESCRIPTION:

	Case party roster management. Links bindings to cases via
	cross-log commentary entries. Query helpers for binding
	discovery.

	Per the v1.6 Event Dictionary (.cleanup-3), parties
	have NO DIDs. The only public reference is the case-local
	`binding_id` minted by `party_binding`; the underlying
	identity (when public) is the `party_name` field.

KEY ARCHITECTURAL DECISIONS:
  - BuildCommentary on the cases log referencing party binding
    position on the parties log.
  - QueryBySignerDID on the parties log to find bindings the
    caller has signed.
  - No SMT mutation — commentary entries are zero-impact.

OVERVIEW:

	PartyLink             — discovered party-case association.
	LinkPartyCaseConfig   — cross-log link config.
	LinkPartyToCase       — cases-log commentary writer.
	ListCaseParties       — discovery on the parties log.
	FindPartyByBindingID  — direct binding lookup.

KEY DEPENDENCIES:
  - schemas (PartyBindingPayload, PartyClass).
  - attesta/builder, log.
*/
package parties

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// PartiesQuerier discovers party binding entries.
// Satisfied by log.LedgerQueryAPI (structural typing).
type PartiesQuerier interface {
	QueryBySignerDID(ctx context.Context, did string) ([]types.EntryWithMetadata, error)
	QueryByTargetRoot(ctx context.Context, pos types.LogPosition) ([]types.EntryWithMetadata, error)
}

// PartyLink represents a discovered party-case association.
// Per v1.6, BindingID is the public reference; PartyName is
// populated only when the binding is unsealed.
type PartyLink struct {
	BindingPos types.LogPosition
	BindingID  string
	PartyClass schemas.PartyClass
	PartyName  string
	Status     string
	CaseRef    string
	IsSealed   bool // when true, the underlying identity is in
	// the sealed mirror; PartyName is empty
}

// LinkPartyCaseConfig configures a cross-log party-case link.
type LinkPartyCaseConfig struct {
	Destination   string
	SignerDID     string            // Court clerk signing the commentary
	CaseRootPos   types.LogPosition // Case root on cases log
	BindingPos    types.LogPosition // Party binding on parties log
	BindingID     string            // Case-local mint (matches the binding's payload)
	PartiesLogDID string            // DID of the parties log
	PartyClass    schemas.PartyClass
	EventTime     int64
}

// LinkPartyToCase publishes a commentary entry on the cases log
// that references a party binding on the parties log.
func LinkPartyToCase(cfg LinkPartyCaseConfig) (*envelope.Entry, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("parties/roster: empty signer DID")
	}
	if cfg.BindingID == "" {
		return nil, fmt.Errorf("parties/roster: empty binding_id")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"link_type":       "party_case_association",
		"binding_id":      cfg.BindingID,
		"party_class":     string(cfg.PartyClass),
		"binding_log_did": cfg.PartiesLogDID,
		"binding_seq":     cfg.BindingPos.Sequence,
	})

	return builder.BuildCommentary(builder.CommentaryParams{
		Destination: cfg.Destination,
		SignerDID:   cfg.SignerDID,
		Payload:     payload,
		EventTime:   cfg.EventTime,
	})
}

// ListCaseParties queries the parties log for all bindings the
// caller signed. Returns discovered party links.
func ListCaseParties(
	ctx context.Context,
	signerDID string,
	querier PartiesQuerier,
) ([]PartyLink, error) {
	entries, err := querier.QueryBySignerDID(ctx, signerDID)
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
			BindingID  string             `json:"binding_id"`
			PartyClass schemas.PartyClass `json:"party_class"`
			PartyName  string             `json:"party_name"`
			CaseRef    string             `json:"case_ref"`
			Status     string             `json:"status"`
		}
		if json.Unmarshal(entry.DomainPayload, &payload) != nil {
			continue
		}
		if payload.BindingID == "" {
			continue
		}

		links = append(links, PartyLink{
			BindingPos: meta.Position,
			BindingID:  payload.BindingID,
			PartyClass: payload.PartyClass,
			PartyName:  payload.PartyName,
			Status:     payload.Status,
			CaseRef:    payload.CaseRef,
			IsSealed:   payload.PartyName == "", // unsealed bindings carry name
		})
	}

	return links, nil
}

// FindPartyByBindingID searches for a party binding by its
// case-local BindingID. The querier scans entries the caller
// signed; matching is on payload.binding_id.
func FindPartyByBindingID(
	ctx context.Context,
	signerDID, bindingID string,
	querier PartiesQuerier,
) (*PartyLink, error) {
	if bindingID == "" {
		return nil, fmt.Errorf("parties/roster: empty binding_id")
	}
	links, err := ListCaseParties(ctx, signerDID, querier)
	if err != nil {
		return nil, err
	}
	for _, l := range links {
		if l.BindingID == bindingID {
			cp := l
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("parties/roster: binding_id %q not found", bindingID)
}
