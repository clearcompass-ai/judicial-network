/*
FILE PATH: internal/testutil/sign.go

DESCRIPTION:
    Test-only helpers for signing entries the way the production
    exchange will. v7.75 forbids serializing an unsigned entry, so
    every domain test that asserts a Serialize/Deserialize round-trip
    must first attach a primary signature.

KEY ARCHITECTURAL DECISIONS:
    - Production code in judicial-network NEVER signs entries. Builders
      produce unsigned entries; the exchange (key custodian) signs and
      submits. This package exists so test authors don't have to
      reproduce the SDK's signing dance in every package.
    - Lives under internal/ so it cannot escape the module.
    - SignEntry returns a fully-signed *envelope.Entry with one
      ECDSA-secp256k1 primary signature whose SignerDID equals the
      header SignerDID — the v7.75 invariant Validate() enforces.
    - GenerateKeyForDID is a test convenience: it returns a signing
      key without claiming any binding between the key and the DID.
      Production DIDs are resolved off-log; tests fake the resolution.
*/
package testutil

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// GenerateSigningKey returns a fresh secp256k1 private key. Fatals
// the test on error.
func GenerateSigningKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("testutil: generate signing key: %v", err)
	}
	return priv
}

// SignEntry attaches a primary ECDSA-secp256k1 signature to the
// (otherwise unsigned) entry produced by a domain builder, then
// returns a re-validated *envelope.Entry. Fatals the test on any
// error so callers can write linear test bodies.
//
// Usage:
//
//	entry := buildUnsignedEntry(t, ...)
//	priv := testutil.GenerateSigningKey(t)
//	signed := testutil.SignEntry(t, entry, priv)
//	raw := envelope.Serialize(signed)
func SignEntry(t testing.TB, entry *envelope.Entry, priv *ecdsa.PrivateKey) *envelope.Entry {
	t.Helper()
	if entry == nil {
		t.Fatal("testutil.SignEntry: nil entry")
	}
	if priv == nil {
		t.Fatal("testutil.SignEntry: nil private key")
	}

	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sigBytes, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("testutil: sign entry: %v", err)
	}

	signed, err := envelope.NewEntry(entry.Header, entry.DomainPayload, []envelope.Signature{
		{
			SignerDID: entry.Header.SignerDID,
			AlgoID:    envelope.SigAlgoECDSA,
			Bytes:     sigBytes,
		},
	})
	if err != nil {
		t.Fatalf("testutil: NewEntry with signature: %v", err)
	}
	return signed
}
