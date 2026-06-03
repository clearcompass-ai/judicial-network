package consortium

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/lifecycle"
	"github.com/baseproof/baseproof/types"
)

const (
	courtDID1     = "did:web:courts.nashville.gov"
	courtDID2     = "did:web:courts.memphis.gov"
	consortiumDID = "did:web:courts.tn.gov:consortium"
	consortiumLog = "did:web:courts.tn.gov:consortium:governance"
)

// ═════════════════════════════════════════════════════════════════════
// Scope creation — consortium formation
// ═════════════════════════════════════════════════════════════════════

func TestScopeCreation_ConsortiumFormation(t *testing.T) {
	authoritySet := map[string]struct{}{
		courtDID1: {},
		courtDID2: {},
	}

	entry, err := builder.BuildScopeCreation(builder.ScopeCreationParams{
		Destination:  "did:web:exchange.test",
		SignerDID:    courtDID1,
		AuthoritySet: authoritySet,
		Payload: mustJSON(t, map[string]any{
			"consortium_name": "Tennessee Court Network",
			"formation_date":  "2027-01-15",
		}),
	})
	if err != nil {
		t.Fatalf("BuildScopeCreation: %v", err)
	}

	// Scope creation: no TargetRoot (creates new leaf).
	if entry.Header.TargetRoot != nil {
		t.Error("scope creation should have nil TargetRoot")
	}

	// AuthoritySet must be populated.
	if len(entry.Header.AuthoritySet) != 2 {
		t.Errorf("AuthoritySet size = %d, want 2", len(entry.Header.AuthoritySet))
	}
	if _, ok := entry.Header.AuthoritySet[courtDID1]; !ok {
		t.Error("court1 should be in AuthoritySet")
	}
	if _, ok := entry.Header.AuthoritySet[courtDID2]; !ok {
		t.Error("court2 should be in AuthoritySet")
	}
}

// ─── Scope creation requires signer in authority set ────────────────

func TestScopeCreation_SignerMustBeInAuthoritySet(t *testing.T) {
	_, err := builder.BuildScopeCreation(builder.ScopeCreationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   courtDID1,
		AuthoritySet: map[string]struct{}{
			courtDID2: {}, // court1 (signer) NOT in set.
		},
		Payload: []byte("{}"),
	})
	if err == nil {
		t.Fatal("expected error when signer not in authority set")
	}
}

// ─── Scope creation requires non-empty authority set ────────────────

func TestScopeCreation_EmptyAuthoritySet_Rejected(t *testing.T) {
	_, err := builder.BuildScopeCreation(builder.ScopeCreationParams{
		Destination:  "did:web:exchange.test",
		SignerDID:    courtDID1,
		AuthoritySet: map[string]struct{}{},
		Payload:      []byte("{}"),
	})
	if err == nil {
		t.Fatal("expected error for empty authority set")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Scope amendment — add member (Path C)
// ═════════════════════════════════════════════════════════════════════

func TestScopeAmendment_AddMember(t *testing.T) {
	scopePos := types.LogPosition{LogDID: consortiumLog, Sequence: 1}
	newMember := "did:web:courts.knoxville.gov"

	entry, err := builder.BuildScopeAmendment(builder.ScopeAmendmentParams{
		Destination:  "did:web:exchange.test",
		SignerDID:    courtDID1,
		TargetRoot:   scopePos,
		ScopePointer: scopePos,
		NewAuthoritySet: map[string]struct{}{
			courtDID1: {},
			courtDID2: {},
			newMember: {},
		},
		Payload: mustJSON(t, map[string]any{
			"action":     "add_member",
			"new_member": newMember,
		}),
	})
	if err != nil {
		t.Fatalf("BuildScopeAmendment: %v", err)
	}

	// Path C: AuthorityScopeAuthority.
	if *entry.Header.AuthorityPath != envelope.AuthorityScopeAuthority {
		t.Error("scope amendment should use Path C (ScopeAuthority)")
	}

	// New authority set includes 3 members.
	if len(entry.Header.AuthoritySet) != 3 {
		t.Errorf("AuthoritySet = %d, want 3", len(entry.Header.AuthoritySet))
	}
}

// ═════════════════════════════════════════════════════════════════════
// Scope removal — remove member (Path C, no AuthoritySet)
// ═════════════════════════════════════════════════════════════════════

func TestScopeRemoval_RemoveMember(t *testing.T) {
	scopePos := types.LogPosition{LogDID: consortiumLog, Sequence: 1}

	entry, err := builder.BuildScopeRemoval(builder.ScopeRemovalParams{
		Destination:  "did:web:exchange.test",
		SignerDID:    courtDID1,
		TargetRoot:   scopePos,
		ScopePointer: scopePos,
		Payload: mustJSON(t, map[string]any{
			"action": "remove_member",
			"target": courtDID2,
		}),
	})
	if err != nil {
		t.Fatalf("BuildScopeRemoval: %v", err)
	}

	// Path C, no AuthoritySet → removal (distinguished from amendment).
	if *entry.Header.AuthorityPath != envelope.AuthorityScopeAuthority {
		t.Error("scope removal should use Path C")
	}
	if len(entry.Header.AuthoritySet) != 0 {
		t.Error("scope removal should have empty AuthoritySet")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Amendment proposal — lifecycle governance
// ═════════════════════════════════════════════════════════════════════

func TestAmendmentProposal_AddAuthority(t *testing.T) {
	proposal, err := lifecycle.ProposeAmendment(lifecycle.AmendmentProposalParams{
		Destination:  "did:web:exchange.test",
		ProposerDID:  courtDID1,
		ProposalType: lifecycle.ProposalAddAuthority,
		TargetDID:    "did:web:courts.knoxville.gov",
		Description:  "Add Knox County to the consortium",
	})
	if err != nil {
		t.Fatalf("ProposeAmendment: %v", err)
	}

	if proposal == nil {
		t.Fatal("proposal is nil")
	}
	if proposal.Entry == nil {
		t.Fatal("proposal.Entry is nil")
	}

	// Proposal is a commentary entry (zero SMT impact).
	if proposal.Entry.Header.TargetRoot != nil {
		t.Error("proposal entry should have nil TargetRoot (commentary)")
	}
}

// ─── Proposal type: remove authority ────────────────────────────────

func TestAmendmentProposal_RemoveAuthority(t *testing.T) {
	proposal, err := lifecycle.ProposeAmendment(lifecycle.AmendmentProposalParams{
		Destination:  "did:web:exchange.test",
		ProposerDID:  courtDID1,
		ProposalType: lifecycle.ProposalRemoveAuthority,
		TargetDID:    courtDID2,
		Description:  "Remove Shelby County — missed SLA",
	})
	if err != nil {
		t.Fatalf("ProposeAmendment remove: %v", err)
	}

	if proposal.Entry == nil {
		t.Fatal("proposal entry nil")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Anchor entry — cross-court anchoring (commentary)
// ═════════════════════════════════════════════════════════════════════

func TestAnchorEntry_CrossCourt(t *testing.T) {
	// County→state cross-court anchoring now uses the single self-contained
	// cosigned_tree_head_v1 format (the SDK owns it). Build a real cosigned
	// head so the embedded quorum is recomputable offline by the state log.
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = byte(i + 3)
	}
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	head := types.TreeHead{
		TreeSize:    42871,
		RootHash:    [32]byte{0xAA},
		SMTRoot:     [32]byte{0xBB},
		ReceiptRoot: [32]byte{0xCC},
	}
	cth := types.CosignedTreeHead{TreeHead: head}
	sig, err := cosign.NewECDSAWitnessSigner(priv).
		Sign(context.Background(), cosign.NewTreeHeadPayload(head), nid, cosign.HashAlgoSHA256)
	if err != nil {
		t.Fatalf("witness Sign: %v", err)
	}
	cth.Signatures = append(cth.Signatures, sig)

	entry, err := anchor.BuildCosignedAnchorEntry(anchor.CosignedAnchorParams{
		Destination:  "did:web:exchange.test",
		SignerDID:    "did:web:ledger.courts.tn.gov",
		SourceLogDID: "did:web:courts.nashville.gov:cases",
		Head:         cth,
		NetworkID:    nid,
	})
	if err != nil {
		t.Fatalf("BuildCosignedAnchorEntry: %v", err)
	}

	// Anchor is commentary — zero SMT impact.
	if entry.Header.TargetRoot != nil {
		t.Error("anchor entry should have nil TargetRoot")
	}
	if entry.Header.AuthorityPath != nil {
		t.Error("anchor entry should have nil AuthorityPath")
	}

	// Payload is the self-contained cosigned_tree_head_v1 shape: the source
	// DID plus the full embedded head (roots + cosignatures), not a bare ref.
	var parsed struct {
		AnchorType   string `json:"anchor_type"`
		SourceLogDID string `json:"source_log_did"`
		Head         struct {
			Head struct {
				TreeSize uint64 `json:"tree_size"`
			} `json:"head"`
		} `json:"head"`
	}
	if err := json.Unmarshal(entry.DomainPayload, &parsed); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if parsed.AnchorType != anchor.CosignedAnchorType {
		t.Errorf("anchor_type = %q, want %s", parsed.AnchorType, anchor.CosignedAnchorType)
	}
	if parsed.SourceLogDID != "did:web:courts.nashville.gov:cases" {
		t.Error("source_log_did mismatch")
	}
	if parsed.Head.Head.TreeSize != 42871 {
		t.Errorf("embedded tree_size = %d, want 42871", parsed.Head.Head.TreeSize)
	}
}

// ═════════════════════════════════════════════════════════════════════
// Cross-log proof types — structural checks
// ═════════════════════════════════════════════════════════════════════

func TestCrossLogProof_TypeStructure(t *testing.T) {
	// Verify the CrossLogProof type has all expected fields.
	proof := types.CrossLogProof{
		SourceEntry:     types.LogPosition{LogDID: "did:web:a:cases", Sequence: 100},
		SourceEntryHash: [32]byte{1, 2, 3},
		AnchorEntry:     types.LogPosition{LogDID: "did:web:anchor", Sequence: 50},
		AnchorEntryHash: [32]byte{4, 5, 6},
	}

	if proof.SourceEntry.Sequence != 100 {
		t.Error("SourceEntry.Sequence mismatch")
	}
	if proof.AnchorEntry.Sequence != 50 {
		t.Error("AnchorEntry.Sequence mismatch")
	}
	if proof.SourceEntryHash == [32]byte{} {
		t.Error("SourceEntryHash should be set")
	}
}

// ═════════════════════════════════════════════════════════════════════
// Mirror entry — cross-log relay
// ═════════════════════════════════════════════════════════════════════

func TestMirrorEntry_CrossLogRelay(t *testing.T) {
	entry, err := builder.BuildMirrorEntry(builder.MirrorParams{
		Destination:    "did:web:exchange.test",
		SignerDID:      courtDID1,
		SourceLogDID:   "did:web:courts.memphis.gov:cases",
		SourcePosition: types.LogPosition{LogDID: "did:web:courts.memphis.gov:cases", Sequence: 200},
	})
	if err != nil {
		t.Fatalf("BuildMirrorEntry: %v", err)
	}

	// Mirror is commentary — zero SMT impact.
	if entry.Header.TargetRoot != nil {
		t.Error("mirror should have nil TargetRoot")
	}

	var parsed map[string]any
	json.Unmarshal(entry.DomainPayload, &parsed)
	if parsed["source_log_did"] != "did:web:courts.memphis.gov:cases" {
		t.Error("source_log_did mismatch in mirror payload")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return b
}
