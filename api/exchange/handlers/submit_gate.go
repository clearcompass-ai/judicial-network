/*
FILE PATH: api/exchange/handlers/submit_gate.go

DESCRIPTION:

	SubmitGater — the per-jurisdiction admission gate run on
	POST /v1/entries/submit before the handler forwards to the
	ledger. Implements 3E.4: every submission is validated
	against the destination Bundle's policies before any bytes
	leave the exchange.

	Gate sequence (when wired):
	  1. Resolve the Bundle from entry.Header.Destination via
	     the registered jurisdiction.Registry.
	  2. Run verification.CheckCosignature against the Bundle's
	     CosignaturePolicy + RoleResolver. Closed-set rejection
	     tokens map to 403 Forbidden bodies.
	  3. Run prerequisites.Walker.Check against the Bundle's
	     PrerequisitePolicy. Hard rejections fail the submit;
	     Advisory violations forward (the aggregator surfaces
	     them).

	The handler treats a nil SubmitGate as the pre-3E.4 pass-
	through proxy — backward-compatible for tests and pre-roster
	deployments. Production deployments wire a *BundleSubmitGate.

OVERVIEW:

	SubmitGater         interface (Admit method).
	Rejection           closed-set rejection envelope.
	BundleSubmitGate    production impl over jurisdiction.Registry.

KEY DEPENDENCIES:
  - jurisdiction.Registry / Bundle.
  - verification.CheckCosignature / RoleResolver.
  - prerequisites.Walker / CaseContext.
*/
package handlers

import (
	"context"
	"errors"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/core/envelope"

	prerequisites "github.com/baseproof/tooling/libs/prereq"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// SubmitGater runs the per-jurisdiction admission gate. Returns
// nil on accept, non-nil on reject. The gate is responsible for
// deserializing the raw entry bytes so the handler stays a pure
// proxy on the no-gate path. Implementations MUST be safe for
// concurrent use.
type SubmitGater interface {
	Admit(ctx context.Context, entryBytes []byte) *Rejection
}

// Rejection is the closed-set output of a SubmitGater. Code is
// stable for audit pipelines; Reason carries human detail.
type Rejection struct {
	Code   string
	Reason string
}

// BundleSubmitGate implements SubmitGater on top of a frozen
// jurisdiction.Registry. Production exchange handlers construct one
// of these at boot via exchange.NewBundleSubmitGate(registry).
type BundleSubmitGate struct {
	// Registry maps destination DID → Bundle. Required, frozen at
	// boot. Lookup keys are entry.Header.Destination values.
	Registry *jurisdiction.Registry

	// Resolver maps cosigner DIDs → role + exchange. OPTIONAL: when
	// nil (the production default) Admit derives a per-entry
	// verification.ChainRoleResolver from the entry's
	// signed_by_capacities block + the destination Bundle's
	// AuthorityChainResolver — so each cosigner's CLAIMED role is
	// VERIFIED against its on-log delegation chain (G19: a self-
	// asserted judge is dropped and does not count toward quorum).
	// Tests may set a verification.MapRoleResolver (trust mode) for a
	// deterministic, chain-free role map.
	Resolver verification.RoleResolver
}

// Admit deserializes entryBytes and runs the cosignature +
// prerequisite gates against the Bundle resolved from
// entry.Header.Destination.
//
// Order:
//  1. envelope.Deserialize → "deserialize_failed" on parse error.
//  2. Resolve Bundle      → "unknown_exchange" on miss.
//  3. Derive RoleResolver → per-entry ChainRoleResolver that verifies
//     each cosigner's claimed role against its on-log delegation chain
//     via the Bundle's AuthorityChainResolver (unless g.Resolver
//     overrides); "malformed_capacities" / "too_many_cosigners" on a
//     bad signed_by_capacities block.
//  4. CheckCosignature    → bubble the verifier rejection.
//  5. Walker.Check        → bubble Hard rejections; Advisory
//     violations are forwarded (treat as accept).
//
// Implementations MUST NOT depend on any aggregator state — the
// gate is the canonical writer-side validator and stands on the
// log alone.
func (g *BundleSubmitGate) Admit(ctx context.Context, entryBytes []byte) *Rejection {
	entry, err := envelope.Deserialize(entryBytes)
	if err != nil {
		return &Rejection{
			Code:   "deserialize_failed",
			Reason: err.Error(),
		}
	}
	if entry == nil || entry.Header.Destination == "" {
		return &Rejection{
			Code:   "missing_destination",
			Reason: "entry header has no Destination",
		}
	}
	bundle, err := g.Registry.Bundle(entry.Header.Destination)
	if err != nil {
		return &Rejection{
			Code:   "unknown_exchange",
			Reason: err.Error(),
		}
	}

	// Cosignature gate. In production the RoleResolver is the VERIFYING
	// verification.ChainRoleResolver: each cosigner's claimed role in
	// signed_by_capacities is checked against its on-log delegation
	// chain via the destination Bundle's AuthorityChainResolver, so a
	// self-asserted judge is dropped (G19). A non-nil g.Resolver
	// overrides this (tests inject a MapRoleResolver — trusted, chain-
	// free). When the Bundle has no AuthorityChainResolver wired the
	// verifier drops every cosigner (fail-closed), so a multi-sig entry
	// is refused rather than admitted on an unverifiable claim.
	resolver := g.Resolver
	if resolver == nil {
		cr, err := verification.NewChainRoleResolver(ctx, entry.DomainPayload, bundle.AuthorityChainResolver())
		if err != nil {
			code := "malformed_capacities"
			if errors.Is(err, attestation.ErrTooManyCosigners) {
				code = "too_many_cosigners"
			}
			return &Rejection{Code: code, Reason: err.Error()}
		}
		resolver = cr
	}
	verdict := verification.CheckCosignature(entry,
		bundle.CosignaturePolicy(),
		resolver,
		bundle.ExchangeDID())
	if !verdict.OK {
		return &Rejection{
			Code:   string(verdict.Rejection),
			Reason: verdict.Reason,
		}
	}

	// Prerequisite gate. The submit handler does not have a
	// case-root subtree scanner today (that's a v0.7.0 follow-
	// on). For v0.5.0 we run the Walker with an empty
	// CaseContext: events with no Hard prereqs (case_initiation,
	// cross-exchange transfers) accept; events with Hard
	// ancestor / authority requirements reject — which is the
	// closed-by-default safety property we want at submission.
	walker := &prerequisites.Walker{Policy: bundle.PrerequisitePolicy()}
	wv := walker.Check(verdict.EventType, prerequisites.EvalContext{})
	if !wv.OK {
		return &Rejection{
			Code:   string(wv.Rejection),
			Reason: wv.Reason,
		}
	}

	return nil
}
