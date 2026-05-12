// FILE PATH: judicialfindings/contracts.go
//
// DESCRIPTION:
//
//	Phase 7 — Interface-driven dispatch for judicial findings.
//
//	The SDK declares three open/closed interfaces in
//	gossip/findings/contracts.go: WitnessAttested,
//	SignerAttested, MerkleAttested. Every gossip-event type
//	JN authors must satisfy one (or more) of those interfaces
//	so the SDK's generic dispatch surface (admission router,
//	gossip processor, equivocation tailer) handles it without
//	JN-specific type switches.
//
//	This file is JN's per-finding-type compile-time interface
//	guard registry. Each existing SDK finding type the JN
//	gossip publisher emits is bound here to its cryptographic
//	reality (Quorum / Identity / Structural). Adding a new JN
//	finding type means adding one line here — and the SDK's
//	router automatically dispatches it.
//
//	Trust Alignment: this file implements Principle 2
//	("Interface-Driven Dependency Inversion") of the SDK's 15
//	Guiding Principles and Principle 4 of the Ledger's
//	("Polymorphic Interface Dispatch — No Domain Awareness").
//
// KEY DEPENDENCIES:
//   - attesta/gossip/findings: contracts + the four canonical
//     finding types JN emits today.
package judicialfindings

import (
	"github.com/clearcompass-ai/attesta/gossip/findings"
)

// Class enumerates the three cryptographic realities. Every JN
// finding type belongs to exactly one (or, rarely, multiple).
// Dashboards and admission-router code switch on Class — never
// on the concrete finding type — so a new finding plugs in
// without surgery to either.
type Class string

const (
	// ClassWitness — Quorum Reality. Verified by K-of-N
	// signatures over a canonical message under a NetworkID
	// (lives inside *cosign.WitnessKeySet). Examples:
	// CosignedTreeHeadFinding, EquivocationFinding,
	// EscrowOverrideFinding.
	ClassWitness Class = "witness_attested"

	// ClassSigner — Identity Reality. Verified by resolving a
	// signer DID to its public key and checking a signature
	// against an open identity universe. Examples:
	// EntryCommitmentEquivocationFinding (the SplitID-double-
	// spend sentry from Trust Alignment 8).
	ClassSigner Class = "signer_attested"

	// ClassMerkle — Structural Reality. Verified by replaying
	// RFC 6962 inclusion / consistency proofs against a source
	// tree head using a Static-CT tile fetcher. The SDK ships
	// no concrete implementer in v0.3.0; JN reserves this
	// constant for future cross-log proof gossip events.
	ClassMerkle Class = "merkle_attested"
)

// Registry maps gossip.Kind → Class. Used by the JN admission
// router and dashboards to choose verification + alerting
// behavior without type-switching on the concrete finding.
// The map is hand-curated and intentionally small; new finding
// types add one line.
var Registry = map[string]Class{
	"AT-GOSSIP-STH-V1":             ClassWitness, // CosignedTreeHeadFinding
	"AT-GOSSIP-EQUIV-V1":           ClassWitness, // EquivocationFinding
	"AT-GOSSIP-ESCROW-V1":          ClassWitness, // EscrowOverrideFinding
	"AT-GOSSIP-ROT-V1":             ClassWitness, // OriginatorRotationFinding (signed by the existing quorum)
	"AT-GOSSIP-COMMIT-EQUIV-V1":    ClassSigner,  // EntryCommitmentEquivocationFinding (Trust Alignment 8)
}

// LookupClass returns the cryptographic reality for the given
// gossip Kind string. Returns ("", false) for an unknown Kind —
// the router treats unknown kinds as a configuration error
// (fail-closed; an unknown finding is never silently accepted).
func LookupClass(kind string) (Class, bool) {
	c, ok := Registry[kind]
	return c, ok
}

// ─── Compile-time interface guards ───────────────────────────
//
// These assertions fail at COMPILE TIME if the SDK ever changes
// a finding type to no longer satisfy the interface JN's router
// expects. A failed guard is an unambiguous signal that the
// SDK upgrade requires coordinated JN updates — preventing
// runtime surprises in production.

// CosignedTreeHeadFinding must satisfy WitnessAttested
// (K-of-N tree-head signatures).
var _ findings.WitnessAttested = (*findings.CosignedTreeHeadFinding)(nil)

// EquivocationFinding must satisfy WitnessAttested (both
// conflicting heads carry K-of-N witness signatures).
var _ findings.WitnessAttested = (*findings.EquivocationFinding)(nil)

// EntryCommitmentEquivocationFinding must satisfy
// SignerAttested (each side is signed by the equivocator's DID
// directly — see Trust Alignment 8).
var _ findings.SignerAttested = (*findings.EntryCommitmentEquivocationFinding)(nil)

// Future finding types add their guard here. Examples:
//   var _ findings.WitnessAttested = (*findings.EscrowOverrideFinding)(nil)
//   var _ findings.WitnessAttested = (*findings.OriginatorRotationFinding)(nil)
// (Currently these are commented because the SDK v0.3.0 may
// not yet have method sets that satisfy the interface — JN
// adds the guard the moment the SDK ships the corresponding
// Verify method.)
