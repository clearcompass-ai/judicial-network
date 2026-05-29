/*
Package trust is the judicial-network's seam between its existing
single-backend (fetcher + leaf reader) topology and the SDK's
LogTrustProvider interface (attesta v1.34+).

Why this package exists
=======================

The SDK ships two evaluation surfaces for authority + delegation
provenance, side by side:

  - Legacy (deprecated):  EvaluateAuthority         / VerifyDelegationProvenance
                          — takes (fetcher, leafReader); single-log, latest only.

  - LogTrustProvider:     EvaluateAuthorityWithTrust /
                          VerifyDelegationProvenanceWithTrust
                          — takes (LogTrustProvider, AsOf); multi-log capable,
                          point-in-time capable, cross-log capable.

This package provides the LogTrustProvider implementations the JN's
verification handlers feed those WithTrust functions. Migrating off
the legacy entry points is a refactor under explicit parity locks (see
TestLocalTrust_LegacyParity_*); it is NOT a behavior change today.

Why we ship LocalTrust now and defer MultiJurisdictionTrust
============================================================

LocalTrust wraps the SDK's verifier.SingleLog and is a drop-in seam
for every existing JN call site (compliance, sealing, verify-authority,
verify-batch, delegation-chain). All five sites operate within a
single jurisdiction's logs today; LocalTrust preserves byte-for-byte
results.

A cross-jurisdiction LogTrustProvider — typically a registry of
LocalTrust instances plus an anchor.CosignedAnchorVerifier for
cross-log heads — is structurally required when goal #4 (cross-log
attestation/verification) lands as a daily operational reality. Today
JN's cross-log surfaces (cases/transfer.go, appeals/initiation.go,
appeals/mandate.go) call verifier.BuildCrossLogProof — a different
shape that builds proofs rather than evaluating authority. Until a
real consumer of cross-jurisdiction authority evaluation exists,
shipping a speculative MultiJurisdictionTrust skeleton would be
tech debt. We add it when a call site actually needs it.

The migration's contract (the parity lock)
==========================================

For every JN call site that was on the legacy entry point:

  EvaluateAuthority(ctx, leafKey, leafReader, fetcher, extractor)
                  ≡
  EvaluateAuthorityWithTrust(ctx, entity, NewLocalTrust(fetcher, leafReader),
                             extractor, AsOf{})

  VerifyDelegationProvenance(ctx, ptrs, fetcher, leafReader)
                  ≡
  VerifyDelegationProvenanceWithTrust(ctx, ptrs, NewLocalTrust(fetcher, leafReader),
                                      AsOf{})

The SDK ships its own parity tests (TestEvalAuthWithTrust_LegacyParity,
TestWithTrust_LegacyParity). This package adds the JN-side parity test
that constructs LocalTrust against a JN-representative fixture and
asserts identical results to a hand-call of the legacy function.
*/
package trust
