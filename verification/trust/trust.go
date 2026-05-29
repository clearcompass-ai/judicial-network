/*
FILE PATH:

	verification/trust/trust.go

DESCRIPTION:

	LocalTrust is the JN's adapter that lets the SDK's WithTrust
	walkers consume the same (EntryFetcher, smt.LeafReader) pair the
	legacy walkers consume. It is a thin shim over verifier.SingleLog
	— that struct is already byte-for-byte parity with the legacy
	walkers; this wrapper exists so the JN's call sites can pass a
	clearly-named "local" provider rather than dropping verifier.
	internals into their function bodies.

	LocalTrust is for SINGLE-JURISDICTION evaluation. Every JN call
	site that takes (fetcher, leafReader) today belongs here.
	Cross-jurisdiction authority evaluation — when a real call site
	needs it — gets a MultiJurisdictionTrust provider in a sibling
	file. We do NOT ship that today; it would be speculative
	infrastructure with no consumer.

KEY ARCHITECTURAL DECISIONS:

  - Wraps verifier.SingleLog directly (no fork, no re-implementation).
    The SDK's TestEvalAuthWithTrust_LegacyParity and
    TestWithTrust_LegacyParity pin parity of SingleLog{F, L} +
    AsOf{} against the legacy entry points. By wrapping SingleLog
    LocalTrust inherits that guarantee.

  - No witness set, no head. SingleLog admits an optional
    WitnessKeySet + CosignedTreeHead; LocalTrust does NOT populate
    them because no current JN call site reads them. When a call
    site needs them (e.g., a future audit endpoint that must
    surface the cosigned head to the caller), add an explicit
    NewLocalTrustWithHead constructor — additive, no compat shim.

  - Compile-time interface check at package init makes accidental
    drift surface at build time, not test time.
*/
package trust

import (
	"context"

	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// LocalTrust is the LogTrustProvider for single-jurisdiction
// evaluation backed by one EntryFetcher + smt.LeafReader pair (the
// JN's existing topology). All three interface methods delegate to
// the SDK's verifier.SingleLog, which the SDK guarantees is byte-
// for-byte equivalent to the legacy single-reader walkers at
// AsOf{}.
//
// This is the only provider PR 3 ships. A MultiJurisdictionTrust
// for cross-log evaluation lands when a real call site demands it.
type LocalTrust struct {
	inner verifier.SingleLog
}

// NewLocalTrust constructs a LocalTrust from the JN's existing
// (fetcher, leafReader) pair. Both must be non-nil — they ARE the
// trust root for the WithTrust walkers — they read the entry +
// leaf state through this pair and return a verdict without any
// additional configuration.
//
// Callers pass the same fetcher + leaf reader pre-v1.36 callers
// passed to the now-deleted legacy single-reader walkers
// (verifier.EvaluateAuthority / VerifyDelegationProvenance).
// LocalTrust wraps verifier.SingleLog, which the SDK preserves
// as the byte-for-byte equivalent of those walkers at AsOf{}.
func NewLocalTrust(fetcher types.EntryFetcher, leafReader smt.LeafReader) LocalTrust {
	return LocalTrust{
		inner: verifier.SingleLog{
			Fetcher:    fetcher,
			LeafReader: leafReader,
		},
	}
}

// TrustRoot delegates to verifier.SingleLog: returns the configured
// (zero) WitnessSet + Head. Never errors — SingleLog is permissive
// by construction.
func (t LocalTrust) TrustRoot(
	ctx context.Context,
	logDID string,
	asOf verifier.AsOf,
) (verifier.TrustRoot, error) {
	return t.inner.TrustRoot(ctx, logDID, asOf)
}

// Entry delegates to verifier.SingleLog: fetches via the wrapped
// EntryFetcher, returns no inclusion proof.
func (t LocalTrust) Entry(
	ctx context.Context,
	pos types.LogPosition,
	asOf verifier.AsOf,
) (verifier.EntryProof, error) {
	return t.inner.Entry(ctx, pos, asOf)
}

// Leaf delegates to verifier.SingleLog: reads via the wrapped
// smt.LeafReader, returns no membership proof.
func (t LocalTrust) Leaf(
	ctx context.Context,
	logDID string,
	key [32]byte,
	asOf verifier.AsOf,
) (verifier.LeafProof, error) {
	return t.inner.Leaf(ctx, logDID, key, asOf)
}

// Compile-time check that LocalTrust satisfies the SDK interface.
// If the SDK ever changes the interface shape, this fails at build.
var _ verifier.LogTrustProvider = LocalTrust{}
