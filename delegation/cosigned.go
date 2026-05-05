/*
FILE PATH: delegation/cosigned.go

DESCRIPTION:

	Inline two-actor (or N-actor) signing for entries that require
	cosignatures. Per the v1.3 Event Dictionary's Tier 2 cosignature
	requirement, every entry submitted by a Tier 2 actor (Prosecutor,
	Defense Counsel, Civil Attorney, Fiduciary, Guardian ad litem)
	MUST be cryptographically cosigned by a Tier 1 holder.

	The wire model is INLINE — one envelope, multiple signatures:

	    entry.Signatures[0] = primary signer (matches Header.SignerDID)
	    entry.Signatures[1..N] = cosigners

	All signers compute and sign the SAME 32-byte SigningPayload
	digest. The wallet UX shows the same EIP-712 typed-data display
	to every signer.

	Concretely for an attorney filing:
	  - The Clerk (Tier 1) builds the envelope (Header.SignerDID =
	    Clerk's DID; payload.filed_by = attorney ID).
	  - The Clerk signs first (Signatures[0]).
	  - The cosignature mix may require an Adjudicator (e.g., for
	    certain motion types per the  policy module).
	  - The Adjudicator signs the SAME digest; Signatures[1] is
	    appended.
	  - The envelope serializes with both signatures.

	For institutional Authority_Set succession (already in 2C.5):
	  - The institutional DID signs first.
	  - Each Authority_Set member signs as a cosigner.
	  - 2-of-3 (or whatever threshold) cosignatures present in
	    Signatures[1..N] satisfies the SDK's verifier.

KEY ARCHITECTURAL DECISIONS:
  - Inline only. The dictionary explicitly chose inline over
    commentary cosignatures. signAndSubmitCosigned never calls
    builder.BuildCosignature; it appends to entry.Signatures.
  - Same digest for every signer. The SDK's SigningPayload is
    computed once before any sign call and shared. A cosigner
    signing a different digest would produce a verifier-rejected
    entry; the contract is "all signatures over the same bytes."
  - Order matters at Signatures[0]. The primary signer MUST be
    Signatures[0] (envelope.Validate enforces equality with
    Header.SignerDID). Cosigners are appended in caller-supplied
    order — auditors see exactly the order the writer requested.
  - Validation up front. The function rejects empty primary,
    empty cosigner DIDs, duplicate DIDs (incl. cosigner == primary),
    and exceeding MaxSignaturesPerEntry (64) before any sign
    call. Failed up-front validation never asks the wallet to
    sign.

OVERVIEW:

	signAndSubmitCosigned — the primitive.
	validateCosigners      — pure structural pre-check.

KEY DEPENDENCIES:
  - delegation/builders_common.go (signOne, validateSerializeSubmit,
    sentinels).
*/
package delegation

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/judicial-network/api/exchange/identity"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// MaxCosigners caps the cosigner count per entry. The SDK's hard
// cap is MaxSignaturesPerEntry (64); leaving room for the primary
// signer leaves 63. We expose a constant so policy consumers can
// reason about it.
const MaxCosigners = 63

// SignAndSubmitCosigned is the inline cosignature pipeline.
// Exported so downstream packages ( cosignature-mix policy,
// future filing builders, contract tests) can call it.
//
// Inputs:
//   - ctx: caller-provided context.
//   - bc: BuildContext (Identity, Submitter, ...).
//   - entry: an unsigned envelope.Entry produced by an SDK builder.
//     entry.Header.SignerDID identifies the primary signer.
//   - display: EIP-712 typed data shown to every signer.
//   - reason: short human-readable string for the wallet UX.
//   - cosigners: list of cosigner DIDs. Each must be distinct from
//     each other and from entry.Header.SignerDID. Empty list is
//     rejected (use signAndSubmit for single-signer entries).
//
// Output: the assigned LogPositionRef. The on-log entry carries
// 1 + len(cosigners) signatures, all over the same SigningPayload
// digest, all with AlgoID=SigAlgoECDSA, all 64-byte raw R||S.
func SignAndSubmitCosigned(
	ctx context.Context,
	bc *BuildContext,
	entry *envelope.Entry,
	display *identity.TypedDataDisplay,
	reason string,
	cosigners []string,
) (schemas.LogPositionRef, error) {
	if bc == nil || bc.Identity == nil || bc.Submitter == nil {
		return schemas.LogPositionRef{}, fmt.Errorf("%w: nil BuildContext / Identity / Submitter", ErrInvalidRequest)
	}
	if entry == nil {
		return schemas.LogPositionRef{}, fmt.Errorf("%w: nil entry", ErrInvalidRequest)
	}
	primary := entry.Header.SignerDID
	if primary == "" {
		return schemas.LogPositionRef{}, fmt.Errorf("%w: entry.Header.SignerDID required", ErrInvalidRequest)
	}
	if err := validateCosigners(primary, cosigners); err != nil {
		return schemas.LogPositionRef{}, err
	}

	// One digest, every signer signs the same bytes.
	digest := sha256.Sum256(envelope.SigningPayload(entry))

	// Signatures[0] is always the primary.
	primarySig, err := signOne(ctx, bc, primary, digest, display, reason)
	if err != nil {
		return schemas.LogPositionRef{}, err
	}
	sigs := make([]envelope.Signature, 0, 1+len(cosigners))
	sigs = append(sigs, primarySig)

	// Cosigners in caller order.
	for _, cosigner := range cosigners {
		s, err := signOne(ctx, bc, cosigner, digest, display, reason)
		if err != nil {
			return schemas.LogPositionRef{}, fmt.Errorf("cosigner %s: %w", cosigner, err)
		}
		sigs = append(sigs, s)
	}

	entry.Signatures = sigs
	return validateSerializeSubmit(ctx, bc, entry)
}

// validateCosigners is the pure structural pre-check. Returns nil
// iff cosigners is non-empty, every entry is non-empty, distinct
// from primary, and distinct from every other cosigner.
func validateCosigners(primary string, cosigners []string) error {
	if len(cosigners) == 0 {
		return fmt.Errorf("%w: cosigners list empty (use signAndSubmit for single-signer)", ErrInvalidRequest)
	}
	if len(cosigners) > MaxCosigners {
		return fmt.Errorf("%w: %d cosigners exceeds cap %d", ErrInvalidRequest, len(cosigners), MaxCosigners)
	}
	seen := make(map[string]struct{}, len(cosigners)+1)
	seen[primary] = struct{}{}
	for i, c := range cosigners {
		if c == "" {
			return fmt.Errorf("%w: cosigners[%d] empty did", ErrInvalidRequest, i)
		}
		if _, dup := seen[c]; dup {
			if c == primary {
				return fmt.Errorf("%w: cosigners[%d]=%q equals primary signer", ErrInvalidRequest, i, c)
			}
			return fmt.Errorf("%w: cosigners[%d]=%q duplicate", ErrInvalidRequest, i, c)
		}
		seen[c] = struct{}{}
	}
	return nil
}
