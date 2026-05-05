/*
FILE PATH: verification/cosignature_check.go

DESCRIPTION:

	 cosignature-mix verifier. Read-side enforcement of
	the v1.4 Event Dictionary's Tier 2 cosignature requirement.

	The verifier walks four inputs:

	  1. envelope.Entry           — the on-log entry under review.
	  2. policy.CosignatureMixPolicy — the (event_type → rule) table.
	  3. RoleResolver             — DID → (role, exchange) lookup.
	                                Replaces the deleted
	                                directory.OfficerRegistry per
	                                the v1.6 "no registries" design.
	  4. exchangeDID              — the verifying exchange's DID
	                                (used for IntraExchangeOnly).

	Returns a typed verdict. The check is closed-set: unknown
	event types are REJECTED (the catalog must enumerate every
	event the network accepts).

	Pipeline:

	  a. Parse `event_type` from payload. Reject if missing.
	  b. Lookup rule for event_type. Reject on miss.
	  c. Parse `filed_by_capacity` from payload.
	     - If rule has NO AllowedFilerRoles: capacity MUST be
	       absent (pure ActorSigner event).
	     - If rule has AllowedFilerRoles: capacity MUST be
	       present + valid + role permitted by the rule.
	  d. If capacity is present, the cosigner DID
	     capacity.did MUST appear in entry.Signatures
	     (anti-impersonation).
	  e. Count cosigners whose role (looked up via RoleResolver)
	     is in rule.RequiredSignerRoles. Must reach
	     rule.EffectiveMinCosigners().
	  f. If rule.IntraExchangeOnly: every Tier 1 cosigner counted
	     must come from the entry's exchange (delegation_ref.log_did
	     equals exchangeDID).
	  g. If capacity is present: every key in
	     rule.RequiredCredentials must be present + non-empty.

OVERVIEW:

	CosignatureRejection — closed-set rejection enum.
	CosignatureVerdict   — verdict struct.
	CheckCosignature     — the entry point.

KEY DEPENDENCIES:
  - schemas (FiledByCapacity, ExtractFiledByCapacity).
  - policy (CosignatureMixPolicy, CosignatureRule).
  - verification.RoleResolver (DID → role + exchange; replaces
    the deleted directory.OfficerRegistry).
  - attesta envelope (Entry).
*/
package verification

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// CosignatureRejection enumerates the closed-set verdict values
// the verifier returns. Audit pipelines key on these strings.
type CosignatureRejection string

const (
	CosigOK                        CosignatureRejection = ""
	CosigRejectMissingEventType    CosignatureRejection = "missing_event_type"
	CosigRejectUnknownEventType    CosignatureRejection = "unknown_event_type"
	CosigRejectMalformedPayload    CosignatureRejection = "malformed_payload"
	CosigRejectCapacityMissing     CosignatureRejection = "capacity_missing"
	CosigRejectCapacityForbidden   CosignatureRejection = "capacity_forbidden"
	CosigRejectCapacityInvalid     CosignatureRejection = "capacity_invalid"
	CosigRejectFilerRoleNotAllowed CosignatureRejection = "filer_role_not_allowed"
	CosigRejectFilerSigMissing     CosignatureRejection = "filer_signature_missing"
	CosigRejectInsufficientSigners CosignatureRejection = "insufficient_signers"
	CosigRejectExchangeMismatch    CosignatureRejection = "exchange_mismatch"
	CosigRejectMissingCredential   CosignatureRejection = "missing_credential"
)

// CosignatureVerdict is the typed result. OK==true iff
// Rejection==CosigOK.
type CosignatureVerdict struct {
	OK              bool
	EventType       string
	Rule            *policy.CosignatureRule
	Capacity        *schemas.FiledByCapacity // nil for pure-signer events
	SignerCosigners []SignerCosigner         // each Tier 1 cosigner observed
	Rejection       CosignatureRejection
	Reason          string
}

// SignerCosigner is one observed Tier 1 cosigner (DID + role +
// exchange). The verifier surfaces this list so audit logs can
// render exactly who cosigned what.
type SignerCosigner struct {
	DID          string
	Role         string
	Exchange     string // delegation_ref.log_did (i.e., institutional DID)
	InAllowedSet bool   // role appears in rule.RequiredSignerRoles
}

// CheckCosignature runs the full verification pipeline. Returns a
// non-nil verdict for every input — never nil. OK is the only
// success indicator; on rejection, Reason carries human-readable
// detail and Rejection is one of the closed-set values.
func CheckCosignature(
	entry *envelope.Entry,
	pol policy.CosignatureMixPolicy,
	resolver RoleResolver,
	exchangeDID string,
) *CosignatureVerdict {
	if entry == nil {
		return rejectVerdict("", CosigRejectMalformedPayload, "nil entry")
	}

	eventType, err := extractEventType(entry.DomainPayload)
	if err != nil {
		return rejectVerdict("", CosigRejectMalformedPayload,
			fmt.Sprintf("payload parse: %v", err))
	}
	if eventType == "" {
		return rejectVerdict("", CosigRejectMissingEventType,
			"payload has no event_type")
	}

	rule, err := pol.Lookup(eventType)
	if err != nil {
		return rejectVerdict(eventType, CosigRejectUnknownEventType,
			fmt.Sprintf("lookup %q: %v", eventType, err))
	}

	cap, present, err := schemas.ExtractFiledByCapacity(entry.DomainPayload)
	if err != nil {
		return rejectVerdict(eventType, CosigRejectCapacityInvalid,
			fmt.Sprintf("extract capacity: %v", err))
	}

	switch {
	case rule.RequiresFiler() && !present:
		return rejectVerdict(eventType, CosigRejectCapacityMissing,
			fmt.Sprintf("event %q requires a filer but payload has no filed_by_capacity", eventType))
	case !rule.RequiresFiler() && present:
		return rejectVerdict(eventType, CosigRejectCapacityForbidden,
			fmt.Sprintf("event %q is signer-only but payload carries filed_by_capacity", eventType))
	}

	if present {
		if err := cap.Validate(); err != nil {
			return rejectVerdict(eventType, CosigRejectCapacityInvalid,
				fmt.Sprintf("capacity validate: %v", err))
		}
		if !rule.PermitsFilerRole(cap.Role) {
			return rejectVerdict(eventType, CosigRejectFilerRoleNotAllowed,
				fmt.Sprintf("filer role %q not in AllowedFilerRoles %v",
					cap.Role, rule.AllowedFilerRoles))
		}
		if !signerListContains(entry.Signatures, cap.DID) {
			return rejectVerdict(eventType, CosigRejectFilerSigMissing,
				fmt.Sprintf("capacity.did %q does not appear in Signatures", cap.DID))
		}
		for _, key := range rule.RequiredCredentials {
			if !cap.HasCredential(key) {
				return rejectVerdict(eventType, CosigRejectMissingCredential,
					fmt.Sprintf("required credential %q absent or empty", key))
			}
		}
	}

	cosigners, rejection, reason := collectSignerCosigners(
		entry.Signatures, cap, rule, resolver, exchangeDID)
	if rejection != CosigOK {
		v := rejectVerdict(eventType, rejection, reason)
		v.Rule = rule
		v.Capacity = cap
		v.SignerCosigners = cosigners
		return v
	}
	return &CosignatureVerdict{
		OK:              true,
		EventType:       eventType,
		Rule:            rule,
		Capacity:        cap,
		SignerCosigners: cosigners,
		Rejection:       CosigOK,
	}
}

// extractEventType pulls the top-level event_type field out of a
// domain payload. Returns "" with no error when the payload is
// not a JSON object.
func extractEventType(payload []byte) (string, error) {
	if len(payload) == 0 {
		return "", nil
	}
	var probe struct {
		EventType string `json:"event_type"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return "", err
	}
	return probe.EventType, nil
}

// signerListContains reports whether any signature in sigs has
// SignerDID == did.
func signerListContains(sigs []envelope.Signature, did string) bool {
	for _, s := range sigs {
		if s.SignerDID == did {
			return true
		}
	}
	return false
}

func rejectVerdict(eventType string, rej CosignatureRejection, reason string) *CosignatureVerdict {
	return &CosignatureVerdict{
		OK:        false,
		EventType: eventType,
		Rejection: rej,
		Reason:    reason,
	}
}
