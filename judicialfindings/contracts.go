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
	"github.com/clearcompass-ai/attesta/gossip"
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

	// ClassSelfAttested — Envelope Reality. The gossip envelope's
	// own cosign signature is the authority; there is no embedded
	// per-side proof to verify. The router runs the SDK Event's
	// Validate() structural check (already invoked by the gossip
	// layer before the envelope is admitted) and returns nil.
	//
	// A ledger fabricating a self-attested event signs its own
	// forgery — the envelope-level signature is the same primitive
	// every other gossip event uses; the difference is that for
	// self-attested kinds there is nothing further to cross-check.
	//
	// Introduced by attesta v0.5.0 for KindGhostLeaf
	// (gossip/findings/ghost_leaf.go): a ledger's public
	// confession of a benign crash-recovery duplicate Tessera
	// leaf. Auditor-facing transparency only — JN's equivocation
	// scanner explicitly does NOT consume this Class.
	ClassSelfAttested Class = "self_attested"
)

// Registry maps gossip.Kind → Class. Used by the JN admission
// router and dashboards to choose verification + alerting
// behavior without type-switching on the concrete finding.
// The map is hand-curated and intentionally small; new finding
// types add one line.
// Classification is by the interface each SDK finding type ACTUALLY
// implements (verified against the SDK source, not its docstrings), because
// the router dispatches via a type assertion to that interface — a Kind whose
// finding does not implement its class's interface can never verify.
//
//	WitnessAttested : CosignedTreeHeadFinding, EquivocationFinding,
//	                  WitnessRotationFinding   — Verify(*cosign.WitnessKeySet)
//	SignerAttested  : EntryCommitmentEquivocationFinding — Verify(ctx, SignerVerifier)
//	MerkleAttested  : CrossLogInclusionFinding — Verify(ctx, TreeHead, TileFetcher)
//	gossip.Event    : EscrowOverrideFinding, OriginatorRotationFinding,
//	                  GhostLeafFinding         — no embedded re-verifiable proof
//	                  on the finding interface (see notes below).
//
// EscrowOverrideFinding carries K-of-N witness cosignatures but does NOT
// implement WitnessAttested (the SDK verifies them via cosign.Verify on the
// reconstructed EscrowOverridePayload). It is still witness-attested in
// substance, so it stays ClassWitness; verifyWitness bridges the missing
// interface by calling cosign.Verify directly. Routing it as ClassSelfAttested
// would silently skip the quorum check — a security downgrade.
//
// OriginatorRotationFinding (the I5 single-identity rotation) is authorized by
// the gossip envelope's old-key signature, already verified by the gossip
// layer before admission; there is no embedded quorum/signer proof on the
// finding. It is ClassSelfAttested — distinct from WitnessRotationFinding
// (KindWitnessRotation), which IS a K-of-N quorum-signed set change.
var Registry = map[string]Class{
	"AT-GOSSIP-STH-V1":          ClassWitness,      // CosignedTreeHeadFinding (WitnessAttested)
	"AT-GOSSIP-EQUIV-V1":        ClassWitness,      // EquivocationFinding (WitnessAttested)
	"AT-GOSSIP-ESCROW-V1":       ClassWitness,      // EscrowOverrideFinding (quorum via cosign.Verify; bridged in verifyWitness)
	"AT-GOSSIP-ROT-V1":          ClassSelfAttested, // OriginatorRotationFinding (I5 envelope authority — NOT quorum-signed)
	"AT-GOSSIP-COMMIT-EQUIV-V1": ClassSigner,       // EntryCommitmentEquivocationFinding (Trust Alignment 8)
	"AT-GOSSIP-GHOST-V1":        ClassSelfAttested, // GhostLeafFinding (attesta v0.5.0)
	"AT-GOSSIP-WITROT-V1":       ClassWitness,      // WitnessRotationFinding (attesta v0.6.0; K-of-N over (old set, new set))
	"AT-GOSSIP-XLOG-INCL-V1":    ClassMerkle,       // CrossLogInclusionFinding (attesta v0.7.0; first MerkleAttested implementer)
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

// GhostLeafFinding (attesta v0.5.0) satisfies only the universal
// gossip.Event contract — deliberately NOT WitnessAttested or
// SignerAttested. The SDK's compile-time pin
// (gossip/findings/ghost_leaf.go: `var _ gossip.Event =
// (*GhostLeafFinding)(nil)`) is mirrored here so a future SDK that
// removes Validate() / CanonicalBytes() / Bindings() / Kind()
// surfaces at JN build time. ClassSelfAttested in Registry above
// gates the router behaviour for this Kind.
var _ gossip.Event = (*findings.GhostLeafFinding)(nil)

// WitnessRotationFinding (attesta v0.6.0) must satisfy
// WitnessAttested. The rotation event is signed by the existing
// K-of-N quorum authorising the topology change; its
// Verify(*cosign.WitnessKeySet) delegates to
// witness.VerifyRotation. Pinned here so a future SDK that
// breaks the K-of-N rotation Verify signature surfaces at JN
// build time, not at runtime when the gossip envelope arrives.
var _ findings.WitnessAttested = (*findings.WitnessRotationFinding)(nil)

// CrossLogInclusionFinding (attesta v0.7.0) is the SDK's first
// concrete MerkleAttested implementer — replays an RFC 6962
// inclusion proof of a foreign log's leaf against a source
// TreeHead via a Static-CT tile fetcher.
var _ findings.MerkleAttested = (*findings.CrossLogInclusionFinding)(nil)

// EscrowOverrideFinding satisfies ONLY gossip.Event — it deliberately does
// NOT implement WitnessAttested even though its Kind is ClassWitness. The
// embedded K-of-N witness cosignatures are verified by cosign.Verify on the
// reconstructed EscrowOverridePayload (the bridge in router.go:verifyWitness),
// NOT through a Verify(*cosign.WitnessKeySet) method. This guard pins the SDK
// reality so a future SDK that DOES add WitnessAttested to this type surfaces
// here (at which point the bridge can be deleted in favour of the interface).
var _ gossip.Event = (*findings.EscrowOverrideFinding)(nil)

// OriginatorRotationFinding satisfies ONLY gossip.Event. Its authority is the
// gossip envelope's old-key signature (verified by the gossip layer pre-
// admission); there is no embedded quorum/signer proof to re-verify, so it is
// ClassSelfAttested. Pinned here so a future SDK that adds a Verify method
// (changing its cryptographic reality) surfaces at JN build time.
var _ gossip.Event = (*findings.OriginatorRotationFinding)(nil)

// Future finding types add their guard here.
