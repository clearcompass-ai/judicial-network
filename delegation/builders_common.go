/*
FILE PATH: delegation/builders_common.go

DESCRIPTION:

	Shared infrastructure for the unified delegation builders
	(issue.go, revoke.go, succession.go). Three concerns:

	  1. Ledger-submit boundary — JN never submits canonical bytes
	     to the ledger directly from caller code. The submitter is
	     dependency-injected via LedgerSubmitter so tests get a
	     fake and production gets the real HTTP client.

	  2. Sign-then-submit pipeline — every builder takes an
	     envelope.Entry, computes the SDK SigningPayload digest,
	     asks the IdentityProvider to sign (Privy in production,
	     StubProvider in tests), attaches the SDK SigAlgoECDSA
	     signature, validates the entry, serializes to canonical
	     bytes, and hands those bytes to the LedgerSubmitter.

	  3. Build context — the dependencies a builder needs
	     (IdentityProvider, LedgerSubmitter, RoleCatalog, clock)
	     live in BuildContext so each builder takes one struct
	     rather than nine arguments.

KEY ARCHITECTURAL DECISIONS:
  - JN holds no signing keys. Every signature flows through
    IdentityProvider.SignDigest, which goes to Privy in
    production and a deterministic stub in tests. The keystore
    package's secp256k1 surface (.3) is reserved for
    system DIDs (institutional/ledger bootstrap), not user
    signing.
  - The signing digest is sha256(SigningPayload(entry)). This is
    the SDK's contract; the IdentityProvider receives the
    already-computed 32-byte digest and signs it verbatim,
    preserving EIP-712-style typed-data display fidelity at
    the wallet UX boundary.
  - The signature wire format is 65-byte SignCompact (v||R||S),
    attached as envelope.SigAlgoECDSA. Compatible with the SDK
    verifier and the ledger's submit gate.

OVERVIEW:

	LedgerSubmitter — the submit interface.
	BuildContext      — the dependency-injection bag.
	signAndSubmit     — pipe entry → digest → sign → attach →
	                    serialize → submit.

KEY DEPENDENCIES:
  - api/exchange/identity (IdentityProvider, SignRequest, etc.)
  - schemas (RoleCatalog)
  - attesta envelope (SigningPayload, Serialize, Validate).
*/
package delegation

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/judicial-network/api/exchange/identity"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// LedgerSubmitter is the seam between JN's delegation builders
// and the ledger's submit endpoint. Implementations:
//   - HTTPLedgerSubmitter (production; posts canonical bytes to
//     the ledger's /v1/submit endpoint).
//   - fakeLedgerSubmitter (tests; captures the bytes for
//     assertion).
type LedgerSubmitter interface {
	// SubmitCanonical posts canonical entry bytes to the ledger
	// and returns the assigned LogPosition. Returns an error
	// wrapping ErrSubmitFailed on transport failure or non-2xx
	// response.
	SubmitCanonical(ctx context.Context, canonical []byte) (schemas.LogPositionRef, error)
}

// BuildContext bundles the dependencies every builder needs.
// Construct once per request; methods read it and produce entries.
type BuildContext struct {
	// Identity is the wallet/JWT provider. SignDigest is called
	// for every entry; tests use a StubProvider.
	Identity identity.IdentityProvider

	// Submitter posts the signed canonical bytes to the ledger.
	Submitter LedgerSubmitter

	// Catalog enforces (granter_role × grantee_role × scope ×
	// duration) policy at issuance time. Required by Issue;
	// optional for Revoke and Succeed (those have other authority
	// sources — the granter who issued the original delegation,
	// or the institutional Authority_Set).
	Catalog schemas.RoleCatalog

	// ExchangeDID is the destination value for the SDK's
	// ControlHeader.Destination field — typically the local
	// court's exchange DID. Required.
	ExchangeDID string

	// InstitutionalDID identifies the deployment; rendered into
	// the EIP-712 typed-data domain Salt so signatures cannot
	// replay across courts. Required.
	InstitutionalDID string

	// Now is the clock. Defaults to time.Now.UTC.
	Now func() time.Time
}

func (bc *BuildContext) now() time.Time {
	if bc.Now != nil {
		return bc.Now()
	}
	return time.Now().UTC()
}

// ─── Sentinel errors ────────────────────────────────────────────────

var (
	// ErrInvalidRequest wraps validation failures on a builder's
	// request struct. Caller-side bug.
	ErrInvalidRequest = errors.New("delegation: invalid request")

	// ErrCatalogRejection wraps a RoleCatalog ValidateGrant
	// rejection. The proposed delegation violates the deployment's
	// role-policy invariants.
	ErrCatalogRejection = errors.New("delegation: catalog rejection")

	// ErrBuildFailed wraps an SDK BuildDelegation/BuildRevocation/
	// BuildSuccession failure. Typically a header-validation issue.
	ErrBuildFailed = errors.New("delegation: build failed")

	// ErrSignFailed wraps an IdentityProvider.SignDigest failure.
	// Distinguish via errors.Is from identity.ErrSignRejected /
	// identity.ErrSignTimeout.
	ErrSignFailed = errors.New("delegation: sign failed")

	// ErrSubmitFailed wraps an LedgerSubmitter failure. Distinct
	// from build/sign errors — submission failures are operationally
	// retryable.
	ErrSubmitFailed = errors.New("delegation: submit failed")
)

// ─── signAndSubmit ──────────────────────────────────────────────────

// signAndSubmit drives the build → sign → submit pipeline for a
// single-signer entry. Cosigned entries (Tier 2 attorney filings,
// Authority_Set succession with explicit cosigner list) use
// signAndSubmitCosigned in cosigned.go.
//
// Inputs:
//   - ctx: caller-provided context for cancellation / deadlines.
//   - bc: BuildContext (Identity, Submitter, ...).
//   - entry: an unsigned envelope.Entry produced by an SDK builder.
//   - display: EIP-712 typed data the wallet renders to the user.
//     Required (court actions cannot be signed as opaque hashes).
//   - reason: short human-readable reason for the wallet UI.
//
// Output: the LogPositionRef the ledger assigned the entry.
func signAndSubmit(
	ctx context.Context,
	bc *BuildContext,
	entry *envelope.Entry,
	display *identity.TypedDataDisplay,
	reason string,
) (schemas.LogPositionRef, error) {
	if bc == nil || bc.Identity == nil || bc.Submitter == nil {
		return schemas.LogPositionRef{}, fmt.Errorf("%w: nil BuildContext / Identity / Submitter", ErrInvalidRequest)
	}
	if entry == nil {
		return schemas.LogPositionRef{}, fmt.Errorf("%w: nil entry", ErrInvalidRequest)
	}

	digest := sha256.Sum256(envelope.SigningPayload(entry))
	primary, err := signOne(ctx, bc, entry.Header.SignerDID, digest, display, reason)
	if err != nil {
		return schemas.LogPositionRef{}, err
	}
	entry.Signatures = []envelope.Signature{primary}
	return validateSerializeSubmit(ctx, bc, entry)
}

// signOne runs one IdentityProvider.SignDigest call against the
// pre-computed 32-byte digest and produces an envelope.Signature
// ready for attachment. Shared by signAndSubmit (primary signer)
// and signAndSubmitCosigned (every signer in turn).
//
// Errors are wrapped with errors.Join(ErrSignFailed, providerErr)
// so callers can errors.Is against either ErrSignFailed (the
// category) or identity.ErrSignRejected / identity.ErrSignTimeout
// (the specific cause).
func signOne(
	ctx context.Context,
	bc *BuildContext,
	signerDID string,
	digest [32]byte,
	display *identity.TypedDataDisplay,
	reason string,
) (envelope.Signature, error) {
	resp, err := bc.Identity.SignDigest(ctx, identity.SignRequest{
		SignerDID: signerDID,
		Digest:    digest,
		Display:   display,
		Reason:    reason,
	})
	if err != nil {
		return envelope.Signature{}, errors.Join(ErrSignFailed, err)
	}
	if resp == nil || len(resp.Signature) == 0 {
		return envelope.Signature{}, fmt.Errorf("%w: provider returned empty signature for %s",
			ErrSignFailed, signerDID)
	}

	// SDK expects 64 bytes for SigAlgoECDSA (R||S); SignCompact
	// returns 65 bytes (recoveryByte||R||S). Strip the recovery
	// byte for wire-format compatibility.
	sigBytes := resp.Signature
	if len(sigBytes) == 65 {
		sigBytes = sigBytes[1:]
	}
	return envelope.Signature{
		SignerDID: signerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sigBytes,
	}, nil
}

// validateSerializeSubmit closes the pipeline: validates the entry
// (signatures attached), serializes to canonical bytes, posts to
// the ledger, returns the assigned LogPositionRef.
func validateSerializeSubmit(
	ctx context.Context,
	bc *BuildContext,
	entry *envelope.Entry,
) (schemas.LogPositionRef, error) {
	if err := entry.Validate(); err != nil {
		return schemas.LogPositionRef{}, fmt.Errorf("%w: post-sign validate: %v", ErrBuildFailed, err)
	}
	canonical, err := envelope.Serialize(entry)
	if err != nil {
		return schemas.LogPositionRef{}, fmt.Errorf("%w: serialize: %v", ErrBuildFailed, err)
	}
	pos, err := bc.Submitter.SubmitCanonical(ctx, canonical)
	if err != nil {
		return schemas.LogPositionRef{}, fmt.Errorf("%w: %v", ErrSubmitFailed, err)
	}
	return pos, nil
}
