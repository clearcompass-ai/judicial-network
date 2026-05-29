/*
FILE PATH:

	schemas/network_topology.go

DESCRIPTION:

	judicial-network-topology-v1 — §16 federation events that
	govern how courts grow, mirror, and (in extremis) fork. Rare
	but foundational: every new court joining the federation,
	every appellate mirror, and every specialty-court division
	flows through these events.

REAL-WORLD USE CASES

	A. Goodlettsville Municipal Court joins the TN network.
	   When a new municipal court onboards, the state log
	   receives an anchor_registration entry establishing the
	   periodic publishing interval that mirrors the new court's
	   log state to the state log for cross-network verification.
	   Action=ActionAnchorRegistration. Operator-flag fields
	   define the interval (typically 1h-24h depending on court
	   volume).

	B. TN Court of Appeals mirrors Davidson Trial Court.
	   So appellate panels can verify trial-court entries during
	   appeals, the COA writes a mirror_creation entry referencing
	   Davidson's exchange_onboarding entry. From that point
	   forward, every Davidson delegation / schema entry is
	   mirrored to the COA log; the COA verifier reads the mirror
	   instead of having to traverse cross-network proofs.

	C. Williamson County leaves the TN system.
	   Rare (career-rare for most courts) but supported. A
	   mirror_revocation entry references the prior
	   mirror_creation; downstream consumers stop accepting
	   delegations from Williamson once the revocation lands.

	D. TN forks into a new network for federal courts.
	   The protocol's worst-case escape hatch. Federal courts
	   that join the TN consortium for state-court coordination
	   may eventually need their own anchor hierarchy; a
	   network_fork entry instantiates the new network referencing
	   the parent's final tip.

	E. Davidson creates a "drug court" division.
	   Davidson splits its general docket into a drug-court
	   division with its own clerk and specialty policies. A
	   scope_division_creation entry references the parent
	   exchange (Davidson) and declares the new division's
	   scope.

SCHEMA SHAPE

	Action discriminator (closed set):
	  - anchor_registration
	  - mirror_creation
	  - mirror_revocation
	  - network_fork
	  - scope_division_creation

	Payload fields are Action-specific; the verifier reads Action
	first and validates the appropriate subset.

KEY ARCHITECTURAL DECISIONS

  - Single schema for 5 events. The §16 federation events share
    the cryptographic-reference-by-LogPosition pattern; one
    schema with an Action discriminator is more maintainable.

  - Network-level, not case-level. None of these carry a
    CaseRootPos — they govern the LOG / network shape, not
    cases.

  - mirror_revocation requires PriorMirrorPos (the
    mirror_creation being revoked) — enforced by both the
    payload requirement and the prerequisite walker.

  - scope_division_creation requires ParentExchangeDID — the
    division is always "of" some parent exchange.

  - network_fork carries ParentTipPos so the new network can
    cryptographically anchor back to the parent's final state
    (the dictionary's "cryptographically links back to the
    final state of the old one" contract).

KEY DEPENDENCIES
  - schemas/registry.go: SchemaRegistration, ErrDeserialize
  - attesta/types: LogPosition
*/
package schemas

import (
	"encoding/json"
	"time"

	"github.com/clearcompass-ai/attesta/types"
)

// SchemaNetworkTopologyV1 is the canonical schema URI.
const SchemaNetworkTopologyV1 = "judicial-network-topology-v1"

// Action discriminator — closed set per dictionary §16.
const (
	ActionAnchorRegistration    = "anchor_registration"
	ActionMirrorCreation        = "mirror_creation"
	ActionMirrorRevocation      = "mirror_revocation"
	ActionNetworkFork           = "network_fork"
	ActionScopeDivisionCreation = "scope_division_creation"
)

// NetworkTopologyPayload is the Domain Payload for all 5 §16
// federation events.
type NetworkTopologyPayload struct {
	// ── SDK well-known ────────────────────────────────────────────
	ActivationDelay int64  `json:"activation_delay,omitempty"`
	MigrationPolicy string `json:"migration_policy,omitempty"`

	// ── Discriminator ─────────────────────────────────────────────

	// Action selects the federation event kind. Required;
	// closed-set per dictionary §16.
	Action string `json:"action"`

	// ── Universal metadata ────────────────────────────────────────

	// IssuedAt is the wall-clock issuance time (UTC). Required.
	IssuedAt time.Time `json:"issued_at"`

	// IssuingDID is the signing principal (the joining court for
	// anchor_registration; the mirroring court for mirror_*;
	// the parent network's chief judicial officer for network_
	// fork; the parent exchange's chief judge for
	// scope_division_creation). Required.
	IssuingDID string `json:"issuing_did"`

	// ── anchor_registration ───────────────────────────────────────

	// ParentLogDID names the parent log this network publishes
	// anchors to. Required for anchor_registration.
	ParentLogDID string `json:"parent_log_did,omitempty"`

	// AnchorIntervalSeconds is the cadence between anchor
	// publications. Per dictionary §16 developer flag, defined
	// by the network in code. Recommended: 3600 (hourly) for
	// busy courts; 86400 (daily) for lower-volume municipal.
	// Required for anchor_registration.
	AnchorIntervalSeconds int64 `json:"anchor_interval_seconds,omitempty"`

	// ── mirror_creation / mirror_revocation ───────────────────────

	// MirroredLogDID is the source log whose entries this
	// mirror tracks. Required for mirror_creation +
	// mirror_revocation.
	MirroredLogDID string `json:"mirrored_log_did,omitempty"`

	// MirroredEntryPos is the specific delegation or schema
	// entry being mirrored (per dictionary §16 mirror_creation
	// "Hard prior entry being mirrored"). Required for
	// mirror_creation.
	MirroredEntryPos types.LogPosition `json:"mirrored_entry_pos,omitempty"`

	// PriorMirrorPos points at the mirror_creation being
	// revoked. Required for mirror_revocation.
	PriorMirrorPos types.LogPosition `json:"prior_mirror_pos,omitempty"`

	// RevocationReason is the human-readable cause for revocation
	// (e.g., "Williamson County withdrew from TN consortium per
	// 2027 reorganization"). Optional but recommended.
	RevocationReason string `json:"revocation_reason,omitempty"`

	// ── network_fork ──────────────────────────────────────────────

	// ParentNetworkDID names the network being forked from.
	// Required for network_fork; empty for the rare case of a
	// fresh-bootstrap network with no parent.
	ParentNetworkDID string `json:"parent_network_did,omitempty"`

	// ParentTipPos points at the parent's final tip — the
	// LogPosition the fork cryptographically anchors back to.
	// Required for network_fork.
	ParentTipPos types.LogPosition `json:"parent_tip_pos,omitempty"`

	// ForkMotivation captures the human-readable reason for
	// the fork. Per dictionary §16, motivations are scalability,
	// jurisdictional independence, or governance separation.
	// Required for network_fork.
	ForkMotivation string `json:"fork_motivation,omitempty"`

	// ── scope_division_creation ───────────────────────────────────

	// ParentExchangeDID names the exchange being subdivided
	// (e.g., did:web:state:tn:davidson when Davidson creates
	// a drug-court division). Required for scope_division_
	// creation.
	ParentExchangeDID string `json:"parent_exchange_did,omitempty"`

	// DivisionName is the human-readable division name
	// (e.g., "drug court", "veterans court", "mental health
	// court"). Required for scope_division_creation.
	DivisionName string `json:"division_name,omitempty"`

	// DivisionScope is the open-ended list of case types,
	// schemas, or other identifiers this division is
	// authorized to handle. Required for scope_division_
	// creation.
	DivisionScope []string `json:"division_scope,omitempty"`
}

func DefaultNetworkTopologyParams() []byte {
	params := map[string]interface{}{
		"identifier_scope": "real_did",
		"migration_policy": "strict",
	}
	b, _ := json.Marshal(params)
	return b
}

func SerializeNetworkTopologyPayload(p *NetworkTopologyPayload) ([]byte, error) {
	return json.Marshal(p)
}

func DeserializeNetworkTopologyPayload(data []byte) (*NetworkTopologyPayload, error) {
	var p NetworkTopologyPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, ErrDeserialize
	}
	return &p, nil
}

func networkTopologyRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaNetworkTopologyV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*NetworkTopologyPayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeNetworkTopologyPayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) {
			return DeserializeNetworkTopologyPayload(data)
		},
		DefaultParams:   DefaultNetworkTopologyParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
