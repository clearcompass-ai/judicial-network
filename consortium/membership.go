package consortium

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// MembershipProposal describes a request to add or remove a consortium member.
type MembershipProposal struct {
	ProposerDID string
	TargetDID   string
	CourtName   string
	Reason      string
}

// ProposeMemberAddition creates a scope amendment proposal to add a
// new member to the consortium authority set.
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

// ProposeMemberRemoval creates a scope amendment proposal to remove a member.
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

// CollectMemberApprovals gathers cosignatures from authority set members.
func CollectMemberApprovals(params lifecycle.CollectApprovalsParams) (*lifecycle.ApprovalStatus, error) {
	return lifecycle.CollectApprovals(params)
}

// ExecuteMemberAddition executes a fully-approved add-member amendment.
// ExecuteAmendment returns *envelope.Entry (a scope amendment entry).
func ExecuteMemberAddition(params lifecycle.ExecuteAmendmentParams) (*envelope.Entry, error) {
	return lifecycle.ExecuteAmendment(params)
}

// ExecuteMemberRemoval initiates scope removal. Starts the time-lock.
func ExecuteMemberRemoval(params lifecycle.RemovalParams) (*lifecycle.RemovalExecution, error) {
	return lifecycle.ExecuteRemoval(params)
}

// ActivateMemberRemoval finalizes a removal after time-lock expires.
// ActivateRemoval returns *envelope.Entry (the activation entry).
func ActivateMemberRemoval(params lifecycle.ActivateRemovalParams) (*envelope.Entry, error) {
	return lifecycle.ActivateRemoval(params)
}

// ActivateWithObjectiveTrigger builds ActivateRemovalParams with evidence
// pointers from objective misbehavior proofs (7-day reduced time-lock).
func ActivateWithObjectiveTrigger(
	executorDID string,
	scopePos types.LogPosition,
	newAuthoritySet map[string]struct{},
	removalEntryPos types.LogPosition,
	triggerPositions []types.LogPosition,
	priorAuthority *types.LogPosition,
) (*envelope.Entry, error) {
	return lifecycle.ActivateRemoval(lifecycle.ActivateRemovalParams{
		ExecutorDID:      executorDID,
		ScopePos:         scopePos,
		NewAuthoritySet:  newAuthoritySet,
		RemovalEntryPos:  removalEntryPos,
		EvidencePointers: triggerPositions,
		PriorAuthority:   priorAuthority,
	})
}
