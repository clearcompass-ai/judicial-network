package aggregator

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// ClassifiedEntry is the result of deserializing and classifying a raw entry.
type ClassifiedEntry struct {
	LogDID        string
	Sequence      uint64
	LogTime       time.Time
	SignerDID     string
	EntryType     string         // "new_case", "amendment", "delegation", "revocation",
	                              // "enforcement", "path_b_order", "cosignature",
	                              // "commentary", "scope_creation", "schema"
	AuthorityPath string         // "same_signer", "delegation", "scope_authority", ""
	TargetRootSeq *uint64        // nil for root entities and commentary
	DelegateDID   *string        // set for delegation entries
	Payload       map[string]any // parsed Domain Payload
	Entry         *envelope.Entry
}

// Deserializer converts raw operator entries into classified domain events.
type Deserializer struct{}

// NewDeserializer creates a new deserializer.
func NewDeserializer() *Deserializer {
	return &Deserializer{}
}

// Classify deserializes a raw entry and classifies it by header shape.
func (d *Deserializer) Classify(logDID string, raw common.RawEntry) (*ClassifiedEntry, error) {
	canonicalBytes, err := hex.DecodeString(raw.CanonicalHex)
	if err != nil {
		return nil, fmt.Errorf("decode canonical: %w", err)
	}

	entry, err := envelope.Deserialize(canonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("deserialize: %w", err)
	}

	h := &entry.Header

	var payload map[string]any
	if len(entry.DomainPayload) > 0 {
		json.Unmarshal(entry.DomainPayload, &payload)
	}
	if payload == nil {
		payload = map[string]any{}
	}

	c := &ClassifiedEntry{
		LogDID:    logDID,
		Sequence:  raw.Sequence,
		SignerDID: h.SignerDID,
		Payload:   payload,
		Entry:     entry,
	}

	if raw.LogTimeUnixMicro != 0 {
		c.LogTime = time.UnixMicro(raw.LogTimeUnixMicro)
	}

	if h.TargetRoot != nil {
		seq := h.TargetRoot.Sequence
		c.TargetRootSeq = &seq
	}

	if h.DelegateDID != nil {
		c.DelegateDID = h.DelegateDID
	}

	if h.AuthorityPath != nil {
		switch *h.AuthorityPath {
		case envelope.AuthoritySameSigner:
			c.AuthorityPath = "same_signer"
		case envelope.AuthorityDelegation:
			c.AuthorityPath = "delegation"
		case envelope.AuthorityScopeAuthority:
			c.AuthorityPath = "scope_authority"
		}
	}

	c.EntryType = d.classifyType(h, c)
	return c, nil
}

func (d *Deserializer) classifyType(h *envelope.ControlHeader, c *ClassifiedEntry) string {
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
		if _, ok := c.Payload["identifier_scope"]; ok {
			return "schema"
		}
		if _, ok := c.Payload["docket_number"]; ok {
			return "new_case"
		}
		return "new_case" // default for root entities
	}

	// Targets an existing entity: has TargetRoot, has AuthorityPath.
	if hasTarget && hasAuthority {
		switch c.AuthorityPath {
		case "same_signer":
			// Amendment or revocation.
			if hasDelegate || d.isRevocation(c.Payload) {
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

func (d *Deserializer) isRevocation(payload map[string]any) bool {
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
