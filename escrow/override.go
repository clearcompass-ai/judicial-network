// FILE PATH: escrow/override.go
//
// DESCRIPTION:
//
//	Phase 6 — Escrow override Purpose binding. When the M-of-N
//	escrow nodes reach quorum on a recovery decision, the
//	aggregated cosignature MUST sign under
//	cosign.PurposeEscrowOverride. Without that purpose tag, the
//	signature lives in a different ECDSA digest space than a
//	tree-head cosignature — making cross-purpose replay
//	(an escrow signature being repurposed as a tree-head
//	authorisation) structurally impossible.
//
//	This file is JN's domain wrapper. It composes:
//	  - cosign.NewEscrowOverridePayload (constructs the 72-byte
//	    canonical payload with the right Purpose tag).
//	  - cosign.Verify (verifies the aggregated cosignature under
//	    the network's WitnessKeySet).
//	  - findings.NewEscrowOverrideFinding (wraps the verified
//	    authorisation for gossip transport).
//
//	Trust Alignment 9: Universal Domain Separation. Trust
//	Alignment 11: Pure Pull-Based Gossip — once the override is
//	authorised, it propagates to auditors via the standard
//	gossip channel.
//
// KEY DEPENDENCIES:
//   - attesta/crypto/cosign: PurposeEscrowOverride, Verify,
//     NewEscrowOverridePayload, HashAlgoSHA256
//   - attesta/gossip/findings: NewEscrowOverrideFinding
//   - attesta/types: WitnessSignature
package escrow

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
)

// ErrEscrowOverride is the top-level sentinel for failures in
// the JN override-binding wrappers. Cryptographic failures bubble
// up the underlying SDK errors via errors.Is.
var ErrEscrowOverride = errors.New("escrow/override: invalid override")

// OverrideAuthorization carries the inputs JN's recovery flow
// has assembled before asking the SDK to validate.
type OverrideAuthorization struct {
	// EscrowID is the 32-byte ID of the escrow being overridden.
	// Typically a deterministic hash over (court_did, holder_did,
	// escrow_purpose). Must be non-zero.
	EscrowID [32]byte

	// DecisionHash is a 32-byte commitment to the governance
	// decision that authorised the override (e.g. SHA-256 of the
	// signed M-of-N voting record). Must be non-zero.
	DecisionHash [32]byte

	// Effective is the unix-second timestamp at which the
	// override takes effect on the network. Must be non-zero.
	Effective uint64

	// Signatures are the K-of-N witness cosignatures over the
	// canonical payload bytes (escrowID ‖ decisionHash ‖
	// effective). The witness set is passed to Verify as
	// *cosign.WitnessKeySet — keys + K + NetworkID + BLS
	// verifier bound together.
	Signatures []types.WitnessSignature
}

// VerifyAndWrap is the single public entry point. It:
//
//  1. Constructs the canonical EscrowOverridePayload (which
//     internally pins PurposeEscrowOverride — the tag that
//     forbids cross-purpose replay).
//  2. Calls cosign.Verify(payload, set, HashAlgoSHA256, sigs).
//     The SDK enforces the K-of-N quorum policy encapsulated in
//     set.Quorum() — JN never passes K as a separate argument.
//  3. On success, wraps the verified authorisation in a
//     findings.EscrowOverrideFinding ready for gossip emission.
//
// VerifyAndWrap fails closed: any cryptographic failure or
// structural anomaly returns an error and produces no finding.
// Callers SHOULD NOT broadcast unverified findings; the gossip
// pipeline trusts but verifies, and a hostile peer cannot forge
// these because the SDK's Verify is the same verification
// auditors run on read.
func VerifyAndWrap(
	auth OverrideAuthorization,
	set *cosign.WitnessKeySet,
) (*findings.EscrowOverrideFinding, error) {
	if set == nil {
		return nil, fmt.Errorf("%w: nil *cosign.WitnessKeySet", ErrEscrowOverride)
	}
	if auth.EscrowID == ([32]byte{}) {
		return nil, fmt.Errorf("%w: zero EscrowID", ErrEscrowOverride)
	}
	if auth.DecisionHash == ([32]byte{}) {
		return nil, fmt.Errorf("%w: zero DecisionHash", ErrEscrowOverride)
	}
	if auth.Effective == 0 {
		return nil, fmt.Errorf("%w: zero Effective", ErrEscrowOverride)
	}
	if len(auth.Signatures) == 0 {
		return nil, fmt.Errorf("%w: no signatures", ErrEscrowOverride)
	}
	payload := cosign.NewEscrowOverridePayload(auth.EscrowID, auth.DecisionHash, auth.Effective)
	result, err := cosign.Verify(payload, set, cosign.HashAlgoSHA256, auth.Signatures)
	if err != nil {
		return nil, fmt.Errorf("%w: cosign verify: %w", ErrEscrowOverride, err)
	}
	if result == nil {
		return nil, fmt.Errorf("%w: nil verify result", ErrEscrowOverride)
	}
	if !result.QuorumReached(set.Quorum()) {
		return nil, fmt.Errorf("%w: quorum not reached (valid=%d total=%d K=%d)",
			ErrEscrowOverride, result.ValidCount, result.Total, set.Quorum())
	}
	finding, err := findings.NewEscrowOverrideFinding(payload, auth.Signatures)
	if err != nil {
		return nil, fmt.Errorf("%w: wrap finding: %w", ErrEscrowOverride, err)
	}
	return finding, nil
}

// PurposeTag returns the protocol-level Purpose tag that
// authorises escrow overrides. Exported as a single point of
// reference; downstream code (gossip emit, audit log entries,
// dashboards) consults this constant rather than typing the
// string inline.
func PurposeTag() cosign.Purpose {
	return cosign.PurposeEscrowOverride
}
