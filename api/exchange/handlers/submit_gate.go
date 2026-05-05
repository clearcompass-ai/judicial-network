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
	"github.com/clearcompass-ai/attesta/core/envelope"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/prerequisites"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// SubmitGater runs the per-jurisdiction admission gate. Returns
// nil on accept, non-nil on reject. The gate is responsible for
// deserializing the raw entry bytes so the handler stays a pure
// proxy on the no-gate path. Implementations MUST be safe for
// concurrent use.
type SubmitGater interface {
	Admit(entryBytes []byte) *Rejection
}

// Rejection is the closed-set output of a SubmitGater. Code is
// stable for audit pipelines; Reason carries human detail.
type Rejection struct {
	Code   string
	Reason string
}

// BundleSubmitGate implements SubmitGater on top of a frozen
// jurisdiction.Registry plus a RoleResolver for cosig checking.
// Production exchange handlers construct one of these at boot.
type BundleSubmitGate struct {
	// Registry maps destination DID → Bundle. Required, frozen at
	// boot. Lookup keys are entry.Header.Destination values.
	Registry *jurisdiction.Registry

	// Resolver maps Signer DIDs → role + destination. Required.
	// Tests may use a verification.MapRoleResolver.
	Resolver verification.RoleResolver
}

// Admit deserializes entryBytes and runs the cosignature +
// prerequisite gates against the Bundle resolved from
// entry.Header.Destination.
//
// Order:
//  1. envelope.Deserialize → "deserialize_failed" on parse error.
//  2. Resolve Bundle      → "unknown_exchange" on miss.
//  3. CheckCosignature    → bubble the verifier rejection.
//  4. Walker.Check        → bubble Hard rejections; Advisory
//     violations are forwarded (treat as accept).
//
// Implementations MUST NOT depend on any aggregator state — the
// gate is the canonical writer-side validator and stands on the
// log alone.
func (g *BundleSubmitGate) Admit(entryBytes []byte) *Rejection {
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

	// Cosignature gate.
	verdict := verification.CheckCosignature(entry,
		bundle.CosignaturePolicy(),
		g.Resolver,
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
	// CaseContext: events with no Hard prereqs (case_initiated,
	// cross-exchange transfers) accept; events with Hard
	// ancestor / authority requirements reject — which is the
	// closed-by-default safety property we want at submission.
	walker := &prerequisites.Walker{Policy: bundle.PrerequisitePolicy()}
	wv := walker.Check(verdict.EventType, prerequisites.CaseContext{})
	if !wv.OK {
		return &Rejection{
			Code:   string(wv.Rejection),
			Reason: wv.Reason,
		}
	}

	return nil
}
