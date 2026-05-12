// FILE PATH: onboarding/bootstrap.go
//
// DESCRIPTION:
//
//	Phase 8 — Bootstrap surface for new courts joining the
//	federation. Wraps the three SDK bootstrap modes:
//
//	  1. HardcodedGenesis: the strongest mode. The genesis
//	     *cosign.WitnessKeySet is compiled into the binary; a
//	     chain of rotations + the latest cosigned head produces
//	     a BootstrapResult certifying the court's current
//	     witness topology.
//
//	  2. AnchorLogSync: the new court starts from the state /
//	     federal log's witness set + an anchor head; the SDK's
//	     TreeHeadClient pulls the chain.
//
//	  3. TrustOnFirstUse: ad-hoc audit mode where an external
//	     auditor accepts a single head + timestamp as the
//	     trust anchor. Strictly weaker; documented for
//	     completeness.
//
//	The wrappers return a JN-friendly BootstrapCertificate that
//	the binary's onboarding CLI subcommand prints as a signed
//	admission record (operator pastes it into the court's
//	deployment manifest).
//
// KEY DEPENDENCIES:
//   - attesta/verifier: HardcodedGenesis, AnchorLogSync,
//     TrustOnFirstUse, BootstrapResult, BootstrapMethod.
//   - attesta/crypto/cosign: WitnessKeySet.
//   - attesta/types: CosignedTreeHead, WitnessRotation.
//   - attesta/witness: TreeHeadClient.
package onboarding

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
	"github.com/clearcompass-ai/attesta/witness"
)

// ErrBootstrap is the top-level sentinel; cryptographic
// failures from the SDK bubble up via errors.Is.
var ErrBootstrap = errors.New("onboarding/bootstrap: failed")

// BootstrapMode names the bootstrap strategy chosen for one
// court. The CLI subcommand maps a --method flag to this.
type BootstrapMode string

const (
	ModeHardcodedGenesis BootstrapMode = "hardcoded-genesis"
	ModeAnchorLogSync    BootstrapMode = "anchor-log-sync"
	ModeTrustOnFirstUse  BootstrapMode = "trust-on-first-use"
)

// BootstrapCertificate is JN's printable admission record. The
// CLI subcommand emits this as both JSON (machine-readable for
// CI / configuration) and a short ASCII summary (operator
// review). Trust Alignment 3 (Cryptographic Topologies):
// network admission is observable on-log + via a portable
// artifact the operator can cross-reference.
type BootstrapCertificate struct {
	Method          BootstrapMode    `json:"method"`
	CourtDID        string           `json:"court_did"`
	NetworkID       string           `json:"network_id_hex"`
	QuorumK         int              `json:"quorum_k"`
	WitnessCount    int              `json:"witness_count"`
	TreeSize        uint64           `json:"verified_tree_size"`
	RootHash        string           `json:"verified_root_hash_hex"`
	EstablishedAt   time.Time        `json:"established_at"`
	TrustAnchorHash string           `json:"trust_anchor_hash_hex"`
	WitnessKeyIDs   []string         `json:"witness_key_ids_hex"`
}

// HardcodedGenesisInput carries the compiled-in trust anchor.
type HardcodedGenesisInput struct {
	CourtDID    string
	GenesisSet  *cosign.WitnessKeySet
	Rotations   []types.WitnessRotation
	LatestHead  types.CosignedTreeHead
}

// HardcodedGenesis runs the SDK's verifier.HardcodedGenesis and
// repackages the result as a BootstrapCertificate.
func HardcodedGenesis(in HardcodedGenesisInput) (*BootstrapCertificate, error) {
	if in.CourtDID == "" {
		return nil, fmt.Errorf("%w: court_did required", ErrBootstrap)
	}
	res, err := verifier.HardcodedGenesis(in.GenesisSet, in.Rotations, in.LatestHead)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBootstrap, err)
	}
	return newCertificate(ModeHardcodedGenesis, in.CourtDID, in.GenesisSet, res), nil
}

// AnchorLogSyncInput carries the anchor (state / federal) log
// the new court trusts.
type AnchorLogSyncInput struct {
	CourtDID     string
	AnchorLogDID string
	AnchorSet    *cosign.WitnessKeySet
	Client       *witness.TreeHeadClient
}

// AnchorLogSync runs the SDK's verifier.AnchorLogSync.
func AnchorLogSync(ctx context.Context, in AnchorLogSyncInput) (*BootstrapCertificate, error) {
	if in.CourtDID == "" {
		return nil, fmt.Errorf("%w: court_did required", ErrBootstrap)
	}
	if in.Client == nil {
		return nil, fmt.Errorf("%w: nil TreeHeadClient", ErrBootstrap)
	}
	res, err := verifier.AnchorLogSync(ctx, in.AnchorLogDID, in.Client, in.AnchorSet)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBootstrap, err)
	}
	return newCertificate(ModeAnchorLogSync, in.CourtDID, in.AnchorSet, res), nil
}

// TrustOnFirstUseInput carries the head + fetched timestamp the
// auditor accepts as a trust anchor.
type TrustOnFirstUseInput struct {
	CourtDID  string
	Head      types.CosignedTreeHead
	FetchedAt time.Time
	NetworkID cosign.NetworkID
}

// TrustOnFirstUse runs the SDK's verifier.TrustOnFirstUse.
// Strictly weaker than the other two — documented + supported
// for ad-hoc external audits.
func TrustOnFirstUse(in TrustOnFirstUseInput) (*BootstrapCertificate, error) {
	if in.CourtDID == "" {
		return nil, fmt.Errorf("%w: court_did required", ErrBootstrap)
	}
	res, err := verifier.TrustOnFirstUse(in.Head, in.FetchedAt, in.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBootstrap, err)
	}
	// TOFU does not carry an originating *WitnessKeySet — the head's
	// own signatures are the only trust evidence. We still emit a
	// certificate but with a placeholder witness summary.
	return newCertificate(ModeTrustOnFirstUse, in.CourtDID, nil, res), nil
}

// newCertificate is the shared formatter. set may be nil for
// TOFU (no compiled-in topology); the certificate carries the
// SDK-reported QuorumK either way.
func newCertificate(mode BootstrapMode, courtDID string, set *cosign.WitnessKeySet, res *verifier.BootstrapResult) *BootstrapCertificate {
	c := &BootstrapCertificate{
		Method:          mode,
		CourtDID:        courtDID,
		QuorumK:         res.QuorumK,
		WitnessCount:    len(res.WitnessKeys),
		TreeSize:        res.VerifiedHead.TreeSize,
		RootHash:        hex.EncodeToString(res.VerifiedHead.RootHash[:]),
		EstablishedAt:   res.EstablishedAt,
		TrustAnchorHash: hex.EncodeToString(res.TrustAnchorHash[:]),
	}
	if set != nil {
		nid := set.NetworkID()
		c.NetworkID = hex.EncodeToString(nid[:])
	}
	c.WitnessKeyIDs = make([]string, 0, len(res.WitnessKeys))
	for _, k := range res.WitnessKeys {
		c.WitnessKeyIDs = append(c.WitnessKeyIDs, hex.EncodeToString(k.ID[:]))
	}
	return c
}

// Summary returns a short human-readable banner the CLI prints
// after a successful bootstrap. Stable string format — ops
// runbooks reference these lines verbatim.
func (c *BootstrapCertificate) Summary() string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf(
		"bootstrap: method=%s court=%s K=%d witnesses=%d tree_size=%d established_at=%s",
		c.Method, c.CourtDID, c.QuorumK, c.WitnessCount,
		c.TreeSize, c.EstablishedAt.UTC().Format(time.RFC3339),
	)
}
