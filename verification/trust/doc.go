/*
Package trust is the judicial-network's seam between its existing
single-backend (fetcher + leaf reader) topology and the SDK's
LogTrustProvider interface (attesta v1.36+).

Why this package exists
=======================

The SDK ships one evaluation surface for authority + delegation
provenance:

  - LogTrustProvider:     EvaluateAuthorityWithTrust /
                          VerifyDelegationProvenanceWithTrust
                          — takes (LogTrustProvider, AsOf); multi-log
                          capable, point-in-time capable, cross-log
                          capable.

Pre-v1.36 the SDK also shipped legacy single-reader walkers
(EvaluateAuthority / VerifyDelegationProvenance). Those were
deprecated in v1.34 and deleted in v1.36 — only the WithTrust
variants survive. This package provides the LogTrustProvider
implementations the JN's verification handlers feed those WithTrust
functions.

Why we ship LocalTrust now and defer MultiJurisdictionTrust
============================================================

LocalTrust wraps the SDK's verifier.SingleLog and is a drop-in seam
for every existing JN call site (compliance, sealing, verify-authority,
verify-batch, delegation-chain). All five sites operate within a
single jurisdiction's logs today; LocalTrust preserves byte-for-byte
the results the deleted legacy walkers used to produce.

A cross-jurisdiction LogTrustProvider — typically a registry of
LocalTrust instances plus an anchor.CosignedAnchorVerifier for
cross-log heads — is structurally required when goal #4 (cross-log
attestation/verification) lands as a daily operational reality.
Today JN's cross-log surfaces (cases/transfer.go, appeals/initiation.go,
appeals/mandate.go) call verifier.BuildCrossLogProof — a different
shape that builds proofs rather than evaluating authority. Until a
real consumer of cross-jurisdiction authority evaluation exists,
shipping a speculative MultiJurisdictionTrust skeleton would be
tech debt. We add it when a call site actually needs it.

The migration's contract (the historical parity lock)
=====================================================

When the legacy entry points still existed (v1.34, v1.35) the JN
side carried explicit parity tests:

  EvaluateAuthority(ctx, leafKey, leafReader, fetcher, extractor)
                  ≡
  EvaluateAuthorityWithTrust(ctx, entity, NewLocalTrust(fetcher, leafReader),
                             extractor, AsOf{})

  VerifyDelegationProvenance(ctx, ptrs, fetcher, leafReader)
                  ≡
  VerifyDelegationProvenanceWithTrust(ctx, ptrs, NewLocalTrust(fetcher, leafReader),
                                      AsOf{})

The SDK ran its own internal parity tests
(TestEvalAuthWithTrust_LegacyParity equivalents). With the legacy
entries now deleted, the parity contract is fulfilled by definition
— there is nothing left to diverge from. LocalTrust is the only
shape the WithTrust walkers consume in single-jurisdiction JN code.
*/
package trust
