/*
Package v2 is the judicial-network's signed-request admission gate
rebuilt on top of the SDK's v1.34 exchange-auth envelope.

What changed from v1
=====================

The pre-v2 (bespoke) shape carried a custom canonical layout:

	signer_did | action | payload | timestamp | nonce [| destination]

with Ed25519 signature verification done inline against an
ed25519.PublicKey resolved via PublicKeyResolver, and a separate
freshness window + strict-forever nonce reservation.

The v2 wire shape contains the SDK envelope as its FIRST field and
adds two JN-specific length-prefixed extensions:

	{
	  "envelope":    { ...sdkauth.SignedRequestEnvelope fields... },
	  "action":      "create_filing",
	  "destination": "did:web:exch:davidson",
	  "signature":   "<base64>"
	}

with SigningBytes laid out as:

	sdk_canonical_bytes
	  || u32_be(len(action)) || action_bytes
	  || u32_be(len(destination)) || destination_bytes

Why this matters
================

 1. EVERY SDK security gate runs against the envelope verbatim —
    nonce reservation, MaxValidityWindow ceiling (1h), clock-skew
    bounds, domain match, ASCII/UTF-8 hygiene, ChainID binding for
    Web3. The JN inherits all of them for free.

 2. SDK's SignatureVerifier registry now dispatches per DID method.
    When ledger#152 #4 lands and the registry admits ML-DSA / SLH-DSA,
    the JN gets PQ admission "free" (algoID is now a wire field, not
    hardcoded Ed25519).

 3. Per-Destination NonceStore routing — the load-bearing
    multi-tenant property pinned by the pre-v2
    TestNonceIsolation_AcrossDestinations — is preserved here at the
    middleware layer (above the envelope). Destination is BOTH a
    signature-bound field (defeats swap-replay) AND a routing key
    into the per-tenant NonceStore namespace.

 4. No bespoke canonical layout to audit. The v2 envelope is the
    SDK envelope + two length-prefixed strings — a forgery requires
    either breaking the SDK envelope (covered by the SDK's audit
    surface) or producing a colliding length-prefixed suffix
    (structurally impossible).

Migration
=========

The pre-v2 (bespoke) shape is DELETED in the same PR that introduces
this package. Every JN caller migrates to v2. No backward-compat
shim. See PR #66.

Consumer ergonomics
===================

The v2 SignerAuth.Wrap method preserves the pre-v2 surface:

	mux := http.NewServeMux()
	mux.Handle("/v1/judicial/case", sa.Wrap(handler))

so handler code is untouched — only the construction shape
changes. Tests in this package pin that contract.
*/
package v2
