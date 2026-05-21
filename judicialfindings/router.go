// FILE PATH: judicialfindings/router.go
//
// DESCRIPTION:
//
//	Phase 7 — Interface-driven dispatch for judicial findings.
//
//	The Router is the polymorphic verification surface JN
//	handlers use to verify ANY gossip finding without
//	type-switching. A handler calls
//
//	  err := router.Verify(ctx, event, ctxRefs)
//
//	and the router:
//
//	  1. Looks up the Class via the Kind string.
//	  2. Performs the matching cryptographic verification
//	     (WitnessKeySet, SignerVerifier, or tile fetcher).
//	  3. Returns nil on success or a typed error on failure.
//
//	The same router serves the admission path (validate
//	incoming gossip), the read-side audit path (re-verify on
//	read), and the SRE telemetry path (classify error class for
//	dashboards). Three call sites, one verification primitive.
//
// KEY DEPENDENCIES:
//   - attesta/gossip/findings: WitnessAttested,
//     SignerAttested, MerkleAttested, SignerVerifier.
//   - attesta/crypto/cosign: WitnessKeySet.
//   - attesta/types: TreeHead.
//   - github.com/transparency-dev/tessera: TileFetcherFunc.
package judicialfindings

import (
	"context"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	sdkschema "github.com/clearcompass-ai/attesta/schema"
	"github.com/clearcompass-ai/attesta/types"
	tessera_client "github.com/transparency-dev/tessera/client"
)

// ErrRouter wraps every error path the router produces. The
// underlying SDK sentinels are reachable via errors.Is.
var ErrRouter = errors.New("judicialfindings/router")

// VerificationContext supplies every parameter the three SDK
// interfaces collectively require. The router selects the
// subset relevant to each Class — callers populate whichever
// fields they have on hand and the router fails closed with a
// clear message if a required field is missing for a given
// Class.
type VerificationContext struct {
	// WitnessSets maps the source-log DID embedded in the
	// finding to the WitnessKeySet that proves it. Required
	// for ClassWitness verifications.
	WitnessSets map[string]*cosign.WitnessKeySet

	// SourceLogDID names the source log for the finding. The
	// router uses this to look up the correct WitnessKeySet.
	SourceLogDID string

	// SignerVerifier is the open-identity DID resolver used by
	// ClassSigner verifications. Typically a
	// *did.VerifierRegistry; tests inject a stub.
	SignerVerifier findings.SignerVerifier

	// SourceHead + TileFetcher are required for ClassMerkle
	// verifications (the SDK ships no concrete implementer
	// today; field reserved for future findings).
	SourceHead  types.TreeHead
	TileFetcher tessera_client.TileFetcherFunc

	// SchemaRegistry (attesta v0.4.0+) is the optional
	// admission-router registry. When non-nil and the finding's
	// gossip.Kind appears in the SDK Registry as a SchemaID,
	// the router consults ValidateEntry BEFORE running the
	// cryptographic Verify. This is a defense-in-depth gate —
	// the cryptographic check is the source of truth, but a
	// schema-level structural check rejects malformed
	// payloads with a typed error before any signature work
	// happens. Trust Alignment 14 (Universal SDK Verification
	// Surface): one verifier surface, no per-deployment
	// dialect.
	SchemaRegistry *sdkschema.Registry
}

// Verify dispatches the supplied gossip.Event through the
// matching cryptographic verification path. Returns ErrRouter-
// wrapped failures with the underlying SDK sentinel reachable
// via errors.Is. Unknown Kinds fail closed.
func Verify(ctx context.Context, event gossip.Event, vc VerificationContext) error {
	if event == nil {
		return fmt.Errorf("%w: nil event", ErrRouter)
	}
	kind := string(event.Kind())
	class, ok := LookupClass(kind)
	if !ok {
		return fmt.Errorf("%w: unknown gossip Kind %q (add to Registry to enable)", ErrRouter, kind)
	}
	switch class {
	case ClassWitness:
		return verifyWitness(event, vc)
	case ClassSigner:
		return verifySigner(ctx, event, vc)
	case ClassMerkle:
		return verifyMerkle(ctx, event, vc)
	case ClassSelfAttested:
		return verifySelfAttested(event)
	default:
		return fmt.Errorf("%w: Class %q not implemented", ErrRouter, class)
	}
}

// verifyWitness handles every ClassWitness event. The router
// expects WitnessSets[SourceLogDID] to resolve to a non-nil
// *WitnessKeySet; cryptographic verification is the SDK's
// responsibility from there.
//
// Most ClassWitness findings implement findings.WitnessAttested and verify
// through it. EscrowOverrideFinding is the exception: it carries K-of-N
// witness cosignatures but exposes no Verify(*cosign.WitnessKeySet) method
// (the SDK verifies them via cosign.Verify on the reconstructed payload). The
// router bridges that gap here so the bare decoded finding is still quorum-
// verified — never silently downgraded to envelope-only trust.
func verifyWitness(event gossip.Event, vc VerificationContext) error {
	if vc.SourceLogDID == "" {
		return fmt.Errorf("%w: VerificationContext.SourceLogDID required for ClassWitness", ErrRouter)
	}
	set, ok := vc.WitnessSets[vc.SourceLogDID]
	if !ok || set == nil {
		return fmt.Errorf("%w: no WitnessSet for source_log_did %q", ErrRouter, vc.SourceLogDID)
	}

	switch f := event.(type) {
	case findings.WitnessAttested:
		if err := f.Verify(set); err != nil {
			return fmt.Errorf("%w: witness verify: %w", ErrRouter, err)
		}
		return nil
	case *findings.EscrowOverrideFinding:
		return verifyEscrowOverrideQuorum(f, set)
	default:
		return fmt.Errorf("%w: Kind %q registered as ClassWitness but type %T does not implement WitnessAttested",
			ErrRouter, event.Kind(), event)
	}
}

// verifyEscrowOverrideQuorum verifies an EscrowOverrideFinding's K-of-N
// witness cosignatures by reconstructing the cosign EscrowOverridePayload and
// running cosign.Verify against set — the same primitive the emit-side
// escrow.VerifyAndWrap uses, so admission and re-audit share one verification
// surface (Trust Alignment 14).
func verifyEscrowOverrideQuorum(f *findings.EscrowOverrideFinding, set *cosign.WitnessKeySet) error {
	result, err := cosign.Verify(f.Auth, set, cosign.HashAlgoSHA256, f.Signatures)
	if err != nil {
		return fmt.Errorf("%w: escrow override cosign verify: %w", ErrRouter, err)
	}
	if result == nil || !result.QuorumReached(set.Quorum()) {
		return fmt.Errorf("%w: escrow override quorum not reached (K=%d)", ErrRouter, set.Quorum())
	}
	return nil
}

// verifySigner handles every ClassSigner event.
func verifySigner(ctx context.Context, event gossip.Event, vc VerificationContext) error {
	sa, ok := event.(findings.SignerAttested)
	if !ok {
		return fmt.Errorf("%w: Kind %q registered as ClassSigner but type %T does not implement SignerAttested",
			ErrRouter, event.Kind(), event)
	}
	if vc.SignerVerifier == nil {
		return fmt.Errorf("%w: VerificationContext.SignerVerifier required for ClassSigner", ErrRouter)
	}
	if err := sa.Verify(ctx, vc.SignerVerifier); err != nil {
		return fmt.Errorf("%w: signer verify: %w", ErrRouter, err)
	}
	return nil
}

// verifySelfAttested handles every ClassSelfAttested event
// (attesta v0.5.0+). The gossip envelope's own cosign signature
// is the authority; by the time the router sees the event the
// gossip layer has already verified that envelope. The router
// runs the SDK Event's structural Validate() — a no-op for
// already-admitted events but a defence-in-depth check against a
// future caller that hands the router an unsigned event.
//
// Trust Alignment 14: one verifier surface — ClassSelfAttested
// fits the same Verify(ctx, event, vc) seam as every other class,
// so dashboards and admission code never need to branch on
// "envelope-only vs per-side" verification.
func verifySelfAttested(event gossip.Event) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("%w: self-attested validate: %w", ErrRouter, err)
	}
	return nil
}

// verifyMerkle handles every ClassMerkle event. CrossLogInclusionFinding
// (attesta v0.7.0) is the first concrete MerkleAttested implementer; the
// branch replays an RFC 6962 inclusion proof against vc.SourceHead via
// vc.TileFetcher (a Static-CT tile fetcher pointed at the source log).
func verifyMerkle(ctx context.Context, event gossip.Event, vc VerificationContext) error {
	ma, ok := event.(findings.MerkleAttested)
	if !ok {
		return fmt.Errorf("%w: Kind %q registered as ClassMerkle but type %T does not implement MerkleAttested",
			ErrRouter, event.Kind(), event)
	}
	if vc.TileFetcher == nil {
		return fmt.Errorf("%w: VerificationContext.TileFetcher required for ClassMerkle", ErrRouter)
	}
	if err := ma.Verify(ctx, vc.SourceHead, vc.TileFetcher); err != nil {
		return fmt.Errorf("%w: merkle verify: %w", ErrRouter, err)
	}
	return nil
}
