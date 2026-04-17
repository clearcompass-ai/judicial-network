/*
FILE PATH: consortium/membership.go

DESCRIPTION:
    Membership management for a judicial consortium. Wraps the SDK's
    scope governance primitives (guide §20.2) with judicial-specific
    membership semantics.

    Add member: ProposeAmendment(ProposalAddAuthority) → CollectApprovals
    → ExecuteAmendment. Requires unanimous consent.

    Remove member: ProposeAmendment(ProposalRemoveAuthority) →
    CollectApprovals → ExecuteRemoval → ActivateRemoval.
    N-1 vote. 90-day time-lock (7-day with objective triggers).

KEY DEPENDENCIES:
    - ortholog-sdk/lifecycle: ProposeAmendment, CollectApprovals,
      ExecuteAmendment, ExecuteRemoval, ActivateRemoval,
      ProposalType constants, AmendmentProposalParams,
      ApprovalCollectionParams, AmendmentExecutionParams,
      RemovalExecutionParams, ActivateRemovalParams (guide §20.2)
    - ortholog-sdk/builder: entry builders for amendments
*/
package consortium

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
)

// MembershipProposal describes a request to add or remove a consortium
// member (a county court's institutional DID).
type MembershipProposal struct {
	// ProposerDID is the authority set member proposing the change.
	ProposerDID string

	// TargetDID is the court DID being added or removed.
	TargetDID string

	// CourtName is a human-readable label (stored in Domain Payload).
	CourtName string

	// Reason documents why the change is proposed.
	Reason string
}

// ObjectiveTrigger identifies an objective misbehavior proof that
// reduces the removal time-lock from 90 days to 7 days.
type ObjectiveTrigger struct {
	// Type is one of: "equivocation", "missed_sla",
	// "escrow_liveness_failure", "unauthorized_action"
	Type string

	// EvidencePointers references on-log entries that constitute proof.
	EvidencePointers []uint64
}

// ProposeMemberAddition creates a scope amendment proposal to add a
// new member to the consortium authority set. Returns the proposal
// entry for submission to the consortium log operator.
func ProposeMemberAddition(proposal MembershipProposal) (*lifecycle.AmendmentProposal, error) {
	if proposal.ProposerDID == "" || proposal.TargetDID == "" {
		return nil, fmt.Errorf("consortium/membership: proposer and target DIDs required")
	}

	payload, err := json.Marshal(map[string]any{
		"action":     "add_member",
		"court_did":  proposal.TargetDID,
		"court_name": proposal.CourtName,
		"reason":     proposal.Reason,
	})
	if err != nil {
		return nil, fmt.Errorf("consortium/membership: marshal payload: %w", err)
	}

	return lifecycle.ProposeAmendment(lifecycle.AmendmentProposalParams{
		ProposerDID:     proposal.ProposerDID,
		ProposalType:    lifecycle.ProposalAddAuthority,
		TargetDID:       proposal.TargetDID,
		Description:     fmt.Sprintf("Add %s to consortium", proposal.CourtName),
		ProposalPayload: payload,
	})
}

// ProposeMemberRemoval creates a scope amendment proposal to remove
// a member from the consortium authority set. N-1 consent required.
// Returns the proposal entry for submission.
func ProposeMemberRemoval(proposal MembershipProposal) (*lifecycle.AmendmentProposal, error) {
	if proposal.ProposerDID == "" || proposal.TargetDID == "" {
		return nil, fmt.Errorf("consortium/membership: proposer and target DIDs required")
	}

	payload, err := json.Marshal(map[string]any{
		"action":     "remove_member",
		"court_did":  proposal.TargetDID,
		"court_name": proposal.CourtName,
		"reason":     proposal.Reason,
	})
	if err != nil {
		return nil, fmt.Errorf("consortium/membership: marshal payload: %w", err)
	}

	return lifecycle.ProposeAmendment(lifecycle.AmendmentProposalParams{
		ProposerDID:     proposal.ProposerDID,
		ProposalType:    lifecycle.ProposalRemoveAuthority,
		TargetDID:       proposal.TargetDID,
		Description:     fmt.Sprintf("Remove %s from consortium", proposal.CourtName),
		ProposalPayload: payload,
	})
}

// CollectMemberApprovals gathers cosignatures from authority set
// members for a pending amendment proposal. Returns the collected
// approval entries.
func CollectMemberApprovals(params lifecycle.ApprovalCollectionParams) (*lifecycle.ApprovalCollection, error) {
	return lifecycle.CollectApprovals(params)
}

// ExecuteMemberAddition executes a fully-approved add-member amendment.
// Requires unanimous consent (all authority set members cosigned).
func ExecuteMemberAddition(params lifecycle.AmendmentExecutionParams) (*lifecycle.AmendmentExecution, error) {
	return lifecycle.ExecuteAmendment(params)
}

// ExecuteMemberRemoval initiates the removal of a member. Creates the
// removal execution entry which starts the time-lock period.
// Default: 90 days. With objective triggers: 7 days.
func ExecuteMemberRemoval(params lifecycle.RemovalExecutionParams) (*lifecycle.RemovalExecution, error) {
	return lifecycle.ExecuteRemoval(params)
}

// ActivateMemberRemoval finalizes a removal after the time-lock
// expires. The target DID is removed from the authority set.
//
// Correction #4: uses ActivateRemoval with EvidencePointers
// referencing objective triggers when applicable.
func ActivateMemberRemoval(params lifecycle.ActivateRemovalParams) (*lifecycle.RemovalActivation, error) {
	return lifecycle.ActivateRemoval(params)
}

// ActivateWithObjectiveTrigger builds ActivateRemovalParams with
// evidence pointers from objective misbehavior proofs, enabling the
// 7-day reduced time-lock.
func ActivateWithObjectiveTrigger(
	executorDID string,
	removalEntryPos uint64,
	triggers []ObjectiveTrigger,
) (*lifecycle.RemovalActivation, error) {
	var evidencePointers []uint64
	for _, t := range triggers {
		evidencePointers = append(evidencePointers, t.EvidencePointers...)
	}

	return lifecycle.ActivateRemoval(lifecycle.ActivateRemovalParams{
		ExecutorDID:      executorDID,
		RemovalEntryPos:  removalEntryPos,
		EvidencePointers: evidencePointers,
	})
}
