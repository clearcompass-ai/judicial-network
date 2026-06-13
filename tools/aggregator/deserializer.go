package aggregator

import (
	"time"

	"github.com/baseproof/baseproof/core/envelope"

	libagg "github.com/baseproof/tooling/libs/aggregator"
)

// ClassifiedEntry is a decoded ledger entry plus its judicial EntryType. The
// agnostic decode (envelope deserialize + header extraction) is the engine's
// job (libs/aggregator.DecodedEntry); this adds the JN's domain classification.
type ClassifiedEntry struct {
	LogDID    string
	Sequence  uint64
	LogTime   time.Time
	SignerDID string
	EntryType string // "new_case", "amendment", "delegation", "revocation",
	// "enforcement", "path_b_order", "cosignature",
	// "commentary", "scope_creation", "schema"
	AuthorityPath string         // "same_signer", "delegation", "scope_authority", ""
	TargetRootSeq *uint64        // nil for root entities and commentary
	DelegateDID   *string        // set for delegation entries
	Payload       map[string]any // parsed Domain Payload
	Entry         *envelope.Entry
}

// classify maps an agnostic DecodedEntry to a judicial ClassifiedEntry by
// header shape. This is the domain half of the old Deserializer.Classify; the
// engine supplies the decoded entry.
func classify(d *libagg.DecodedEntry) *ClassifiedEntry {
	c := &ClassifiedEntry{
		LogDID:        d.LogDID,
		Sequence:      d.Sequence,
		LogTime:       d.LogTime,
		SignerDID:     d.SignerDID,
		AuthorityPath: d.AuthorityPath,
		TargetRootSeq: d.TargetRootSeq,
		DelegateDID:   d.DelegateDID,
		Payload:       d.Payload,
		Entry:         d.Entry,
	}
	c.EntryType = classifyType(d)
	return c
}

func classifyType(d *libagg.DecodedEntry) string {
	// PLATFORM REGISTRY KINDS (rc10): a payload carrying a registry `kind`
	// discriminator is classified by it, never by header shape — the kind
	// IS the type. The projector owns the per-kind dispatch (destination
	// lifecycle projects; delegation/credential/burn/genesis are
	// deliberately inert here until their consumer waves).
	if k, _ := d.Payload["kind"].(string); k != "" && isPlatformRegistryKind(k) {
		return "platform_kind"
	}
	h := &d.Entry.Header
	hasTarget := h.TargetRoot != nil
	hasAuthority := h.AuthorityPath != nil
	hasDelegate := h.DelegateDID != nil
	hasAuthoritySet := len(h.AuthoritySet) > 0
	hasCosigOf := h.CosignatureOf != nil

	// Commentary: no TargetRoot, no AuthorityPath.
	if !hasTarget && !hasAuthority {
		if hasCosigOf {
			return "cosignature"
		}
		return "commentary"
	}

	// New entity: no TargetRoot, has AuthorityPath.
	if !hasTarget && hasAuthority {
		if hasDelegate {
			return "delegation"
		}
		if hasAuthoritySet {
			return "scope_creation"
		}
		// Check payload for schema indicators.
		if _, ok := d.Payload["identifier_scope"]; ok {
			return "schema"
		}
		if _, ok := d.Payload["docket_number"]; ok {
			return "new_case"
		}
		return "new_case" // default for root entities
	}

	// Targets an existing entity: has TargetRoot, has AuthorityPath.
	if hasTarget && hasAuthority {
		switch d.AuthorityPath {
		case "same_signer":
			// Amendment or revocation.
			if hasDelegate || isRevocation(d.Payload) {
				return "revocation"
			}
			return "amendment"
		case "delegation":
			return "path_b_order"
		case "scope_authority":
			return "enforcement"
		}
	}

	return "unknown"
}

func isRevocation(payload map[string]any) bool {
	if reason, ok := payload["reason"]; ok {
		if s, ok := reason.(string); ok && s != "" {
			return true
		}
	}
	if _, ok := payload["revocation"]; ok {
		return true
	}
	return false
}
