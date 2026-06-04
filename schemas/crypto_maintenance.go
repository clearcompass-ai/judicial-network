/*
FILE PATH:

	schemas/crypto_maintenance.go

DESCRIPTION:

	judicial-crypto-maintenance-v1 — the §14 continuity events
	that let courts rotate signing keys and recover from key
	compromise/loss without invalidating historical bundles.

REAL-WORLD USE CASES

	A. Routine HSM cert rotation. Davidson Clerk's HSM cert is
	   approaching expiration (12 months from issuance). IT
	   provisions a new cert; the clerk's key authority chain is
	   updated on-log via institutional_key_rotation. Action=
	   ActionInstitutionalKeyRotation. The rotation is signed
	   by the OUTGOING key (last action of the old key) so the
	   chain is cryptographically continuous; historical bundles
	   verified against the old key continue to verify because
	   the rotation entry establishes the new key without
	   abandoning the old.

	B. Judge dies in office. Judge Stevens dies unexpectedly mid-
	   term; the elected judge's signing capability is lost. The
	   designated M-of-N escrow quorum (3-of-5 in TN: chief judge
	   + 2 senior judges) executes mofn_escrow_recovery_execution
	   to reconstitute signing authority on new hardware for
	   ongoing cases. Action=ActionMofNEscrowRecoveryExecution.
	   ThresholdM + ThresholdN capture the quorum parameters;
	   RecoveryReason is the human-readable cause.

SCHEMA SHAPE

	Action (closed set): institutional_key_rotation,
	mofn_escrow_recovery_execution.

	Per-Action fields:
	  - Rotation: OutgoingKeyID, NewKeyID, OldChainTipPos.
	  - Recovery: ThresholdM, ThresholdN, ParticipatingDIDs,
	              RecoveryReason, RecoveredPrincipalDID,
	              NewKeyID.

KEY ARCHITECTURAL DECISIONS

  - Generic schema. URI is "judicial-crypto-maintenance-v1".

  - The escrow recovery threshold (M-of-N) is captured IN the
    payload (not in the schema parameters) so different
    network policies can be expressed without schema bumps.
    Per dictionary §14 developer flag, the threshold is defined
    by the network in code; the payload field is the schema's
    parameter when the network exposes one.

  - Rotation chain integrity. OldChainTipPos points at the
    LAST entry signed by the outgoing key — establishing
    cryptographic continuity. Year-15 verifiers re-walk this
    chain to confirm that no key was abandoned silently.

KEY DEPENDENCIES
  - schemas/registry.go: SchemaRegistration, ErrDeserialize
  - baseproof/types: LogPosition
*/
package schemas

import (
	"encoding/json"
	"time"

	"github.com/baseproof/baseproof/types"
)

// SchemaCryptoMaintenanceV1 is the canonical schema URI.
const SchemaCryptoMaintenanceV1 = "judicial-crypto-maintenance-v1"

// Action discriminator — closed set per dictionary §14.
const (
	ActionInstitutionalKeyRotation    = "institutional_key_rotation"
	ActionMofNEscrowRecoveryExecution = "mofn_escrow_recovery_execution"
)

// CryptoMaintenancePayload is the Domain Payload for both §14
// continuity events.
type CryptoMaintenancePayload struct {
	// ── SDK well-known ────────────────────────────────────────────
	ActivationDelay int64  `json:"activation_delay,omitempty"`
	MigrationPolicy string `json:"migration_policy,omitempty"`

	// ── Discriminator + universal metadata ────────────────────────

	Action     string    `json:"action"`
	IssuedAt   time.Time `json:"issued_at"`
	IssuingDID string    `json:"issuing_did"`

	// ── institutional_key_rotation ────────────────────────────────

	// OutgoingKeyID identifies the key being retired (the cert
	// fingerprint or key-DID). Required for rotation.
	OutgoingKeyID string `json:"outgoing_key_id,omitempty"`

	// NewKeyID identifies the replacement key. Required for
	// rotation + recovery.
	NewKeyID string `json:"new_key_id,omitempty"`

	// OldChainTipPos points at the last entry signed by the
	// OutgoingKey, establishing cryptographic continuity for
	// year-15 chain re-walks. Required for rotation.
	OldChainTipPos types.LogPosition `json:"old_chain_tip_pos,omitempty"`

	// ── mofn_escrow_recovery_execution ────────────────────────────

	// ThresholdM is the required-cooperation count (e.g., 3 of
	// the 5 escrow shareholders must cooperate). Required for
	// recovery.
	ThresholdM int `json:"threshold_m,omitempty"`

	// ThresholdN is the total escrow shareholder count.
	// Required for recovery.
	ThresholdN int `json:"threshold_n,omitempty"`

	// ParticipatingDIDs lists the escrow shareholders who
	// cooperated to execute the recovery (length must be ≥
	// ThresholdM at admission time). Required for recovery.
	ParticipatingDIDs []string `json:"participating_dids,omitempty"`

	// RecoveryReason is the human-readable cause for the
	// recovery (e.g., "Judge Stevens died in office 2027-06-15;
	// designated 3-of-5 quorum reconstructed signing capacity
	// for 47 pending cases"). Required for recovery.
	RecoveryReason string `json:"recovery_reason,omitempty"`

	// RecoveredPrincipalDID is the DID whose signing capacity
	// is being reconstructed (the deceased / incapacitated
	// principal). Required for recovery.
	RecoveredPrincipalDID string `json:"recovered_principal_did,omitempty"`
}

func DefaultCryptoMaintenanceParams() []byte {
	params := map[string]interface{}{
		"identifier_scope": "real_did",
		"migration_policy": "strict",
	}
	b, _ := json.Marshal(params)
	return b
}

func SerializeCryptoMaintenancePayload(p *CryptoMaintenancePayload) ([]byte, error) {
	return json.Marshal(p)
}

func DeserializeCryptoMaintenancePayload(data []byte) (*CryptoMaintenancePayload, error) {
	var p CryptoMaintenancePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, ErrDeserialize
	}
	return &p, nil
}

func cryptoMaintenanceRegistration() *SchemaRegistration {
	return &SchemaRegistration{
		URI: SchemaCryptoMaintenanceV1,
		Serialize: func(payload interface{}) ([]byte, error) {
			p, ok := payload.(*CryptoMaintenancePayload)
			if !ok {
				return nil, ErrDeserialize
			}
			return SerializeCryptoMaintenancePayload(p)
		},
		Deserialize: func(data []byte) (interface{}, error) {
			return DeserializeCryptoMaintenancePayload(data)
		},
		DefaultParams:   DefaultCryptoMaintenanceParams,
		IdentifierScope: IdentifierScopeRealDID,
	}
}
