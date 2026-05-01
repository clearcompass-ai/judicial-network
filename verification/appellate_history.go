/*
FILE PATH: verification/appellate_history.go

DESCRIPTION:
    Appeal chain reconstruction across logs. Topology-agnostic
    after the v0.7.0 refactor: the walker follows cross-log
    references for as many hops as exist, supporting any
    appellate topology:

      TN COA only      trial → COA              (2-level)
      TN with Sup Ct   trial → COA → Sup Ct     (3-level)
      Federal          district → circuit       (2-level)
      Federal w/ SCOTUS district → circuit → SCOTUS (3-level)
      En-banc rehear   plus an extra link at any level

    The chain length is the depth of the topology, not a fixed
    constant. AppealStep.Step is the 1-indexed position; no
    enumerated "Level" field.

KEY ARCHITECTURAL DECISIONS:
    - Walker is topology-agnostic: it terminates when a step's
      cross-log proof has no successor, not when it reaches a
      hard-coded "supreme" level.
    - VerifyAppealChain re-verifies every cross-log proof
      against the source log's witness key set.
    - WalkAppealChain (NEW) constructs the chain by following
      successor proofs supplied by a NextProofFn callback —
      caller plugs in operator-fetch logic.

OVERVIEW:
    AppealStep        — one hop in the chain.
    NextProofFn       — caller-supplied successor lookup.
    WalkAppealChain   — unbounded walker.
    VerifyAppealChain — per-step proof verification.
*/
package verification

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/topology"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// AppealStep is one hop in an appeal chain. The chain is
// ordered from the originating (lowest) log to the final
// (highest) log; Step is 1-indexed.
type AppealStep struct {
	// Step is the 1-indexed depth in the chain. The first step
	// (originating log) is Step=1.
	Step int

	// CasePos identifies the case-root entry on this log.
	CasePos types.LogPosition

	// LogDID is the institutional DID of the log holding this
	// step's case-root entry.
	LogDID string

	// Outcome echoes the appellate disposition outcome (or empty
	// for the trial-level origin step).
	Outcome string

	// Proof is the cross-log proof linking this step to the
	// previous one. Nil at Step=1 (the origin has no predecessor).
	Proof *types.CrossLogProof

	// ProofVerified is set by VerifyAppealChain after the proof
	// passes BLS witness-quorum verification.
	ProofVerified bool
}

// NextProofFn is the caller-supplied successor lookup. Given
// the current step (the chain tail), returns:
//   - the next AppealStep (with Proof linking back to current),
//     or nil to terminate the chain.
//   - any non-nil error halts the walk (ignored if the next
//     step is nil; the walk simply terminates without error).
//
// Production callers wire an operator-fetch implementation that
// reads the successor's case-root entry from the next log via
// the cross-log reference embedded in current's payload.
type NextProofFn func(current AppealStep) (*AppealStep, error)

// WalkAppealChain constructs the appeal chain by repeatedly
// calling next() until it returns nil. The chain is unbounded;
// supports any topology (TN 2-level, TN 3-level with Sup Ct,
// federal, etc.).
//
// The first call yields the origin step (chain length 1);
// subsequent calls extend the chain. WalkAppealChain assigns
// Step indices in order.
//
// To bound the chain (e.g., reject pathological circular
// references), wrap next() in a counter that returns nil after
// a max-depth threshold. The walker itself imposes no cap.
func WalkAppealChain(origin AppealStep, next NextProofFn) ([]AppealStep, error) {
	if next == nil {
		return nil, fmt.Errorf("verification/appellate_history: nil NextProofFn")
	}
	origin.Step = 1
	chain := []AppealStep{origin}
	for {
		current := chain[len(chain)-1]
		nextStep, err := next(current)
		if err != nil {
			return chain, fmt.Errorf("verification/appellate_history: walk halted at step %d: %w",
				current.Step, err)
		}
		if nextStep == nil {
			return chain, nil
		}
		nextStep.Step = current.Step + 1
		chain = append(chain, *nextStep)
	}
}

// VerifyAppealChain verifies a sequence of cross-log appeal
// references. Each step's cross-log proof is verified against
// the source-log witness key set. Returns the chain with
// ProofVerified set per step; halts on the first broken link.
//
// witnessKeysByLog and quorumByLog are keyed by LogDID. A step
// whose LogDID is unknown to the maps is treated as
// ProofVerified=false.
func VerifyAppealChain(
	steps []AppealStep,
	witnessKeysByLog map[string][]types.WitnessPublicKey,
	quorumByLog map[string]int,
	blsVerifier signatures.BLSVerifier,
) ([]AppealStep, error) {
	for i := range steps {
		if steps[i].Proof == nil {
			continue
		}
		sourceKeys := witnessKeysByLog[steps[i].LogDID]
		quorum := quorumByLog[steps[i].LogDID]
		if len(sourceKeys) == 0 || quorum == 0 {
			steps[i].ProofVerified = false
			continue
		}
		err := verifier.VerifyCrossLogProof(*steps[i].Proof,
			sourceKeys, quorum, blsVerifier,
			topology.ExtractAnchorPayload)
		if err != nil {
			steps[i].ProofVerified = false
			continue
		}
		steps[i].ProofVerified = true
	}

	// Verify chain continuity.
	for i := 1; i < len(steps); i++ {
		if !steps[i].ProofVerified {
			return steps, fmt.Errorf("verification/appellate_history: broken at step %d",
				i)
		}
	}
	return steps, nil
}
