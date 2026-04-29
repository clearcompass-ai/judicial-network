/*
FILE PATH: schemas/commutative_ops.go
DESCRIPTION: Judicial-domain enum of commutative-operation codes that
    populate types.SchemaParameters.CommutativeOperations ([]uint32).

KEY ARCHITECTURAL DECISIONS:
    - SDK v7.75 moved CommutativeOperations from ControlHeader to
      SchemaParameters and re-typed it as []uint32. The codes are
      domain-interpreted; the SDK never inspects them.
    - The judicial network owns this enum. Every commutative-op code
      consumed by judicial schemas must appear here. Stable, additive
      only — never reuse a value, never delete one.
    - The SDK's Δ-window OCC machinery (Decision 37 / SDK-D7) keys on
      the uint32 itself — schemas referencing the same code commute.
*/
package schemas

// Reserve 1-99 for protocol-level commutative ops, 100+ for domain-
// specific patterns. Witness attestation is the only one in v1.
const (
	// CommutativeOpWitnessAttestation: an attestation entry whose
	// payload commutes with concurrent attestations against the same
	// target. Used for cosignature-style witness flows where N-of-K
	// attesters can publish independently within the Δ-window without
	// strict ordering.
	CommutativeOpWitnessAttestation uint32 = 1
)
