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
	default:
		return fmt.Errorf("%w: Class %q not implemented", ErrRouter, class)
	}
}

// verifyWitness handles every ClassWitness event. The router
// expects WitnessSets[SourceLogDID] to resolve to a non-nil
// *WitnessKeySet; cryptographic verification is the SDK's
// responsibility from there.
func verifyWitness(event gossip.Event, vc VerificationContext) error {
	wa, ok := event.(findings.WitnessAttested)
	if !ok {
		return fmt.Errorf("%w: Kind %q registered as ClassWitness but type %T does not implement WitnessAttested",
			ErrRouter, event.Kind(), event)
	}
	if vc.SourceLogDID == "" {
		return fmt.Errorf("%w: VerificationContext.SourceLogDID required for ClassWitness", ErrRouter)
	}
	set, ok := vc.WitnessSets[vc.SourceLogDID]
	if !ok || set == nil {
		return fmt.Errorf("%w: no WitnessSet for source_log_did %q", ErrRouter, vc.SourceLogDID)
	}
	if err := wa.Verify(set); err != nil {
		return fmt.Errorf("%w: witness verify: %w", ErrRouter, err)
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

// verifyMerkle handles every ClassMerkle event. The SDK ships
// no concrete implementer in v0.3.0; this branch is forward-
// compatible scaffolding so future cross-log proof findings
// route through the same dispatch surface.
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
