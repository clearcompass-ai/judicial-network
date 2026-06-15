package scenario

// Deterministic principal-identity derivation for the scenario population.
//
// Every principal (judge, justice, clerk, attorney, and the institutional
// root) is a pure function of (masterSeed, label): the same inputs always
// yield the same private key + DID, on any machine. This makes a seeded run
// byte-for-byte REPRODUCIBLE — the registry carries no random state, and a
// re-run provisions the very same officers onto the very same DIDs.
//
// Construction mirrors tooling/libs/loadgen (the backfill deriver): a
// domain-separated hash → a 32-byte secp256k1 scalar → a dcrd private key →
// the SDK's self-certifying did:key. The did:key embeds the public key that
// signs, so the ledger admits a signature under it with no external key
// resolution — exactly as it would a randomly-generated key. No crypto is
// reimplemented here: the scalar is a stdlib SHA-256 expansion and the DID is
// the SDK encoder.
//
// We keep the dcrd *secp256k1.PrivateKey (not crypto/ecdsa) because that is
// what BOTH the IdentityProvider stub (BindKey) and the did:key encoder
// consume; converting through crypto/ecdsa would only lose the type.

import (
	"crypto/sha256"
	"fmt"

	sdkdid "github.com/baseproof/baseproof/did"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// keyDomain is the versioned domain separator for scenario identity
// derivation. Bump the version suffix to rotate the entire scenario keyspace.
const keyDomain = "judicial-network/scenario/secp256k1/v1"

// keyID is one deterministically-derived signer: a dcrd secp256k1 key and its
// self-certifying did:key.
type keyID struct {
	DID  string
	Priv *secp256k1.PrivateKey
}

// deriveScalar expands (masterSeed, label, counter) into a 32-byte candidate
// scalar. counter is bumped only on the astronomically rare invalid-scalar
// retry, so counter==0 is the deterministic norm.
func deriveScalar(masterSeed []byte, label string, counter uint8) [32]byte {
	h := sha256.New()
	h.Write([]byte(keyDomain))
	h.Write([]byte{0x00})
	h.Write(masterSeed)
	h.Write([]byte{0x00})
	h.Write([]byte(label))
	h.Write([]byte{0x00, counter})
	var scalar [32]byte
	copy(scalar[:], h.Sum(nil))
	return scalar
}

// deriveIdentity returns the deterministic identity for label under masterSeed.
// It is a pure function of its inputs. The zero/invalid scalar (≈2⁻¹²⁸) is the
// only failure mode; the counter retry makes derivation never fail in practice
// while staying deterministic.
func deriveIdentity(masterSeed []byte, label string) keyID {
	for counter := uint8(0); counter < 64; counter++ {
		scalar := deriveScalar(masterSeed, label, counter)
		priv := secp256k1.PrivKeyFromBytes(scalar[:]) // interprets bytes mod n
		if priv == nil || priv.Key.IsZero() {
			continue
		}
		compressed := priv.PubKey().SerializeCompressed() // 33-byte sec1
		return keyID{
			DID:  sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed),
			Priv: priv,
		}
	}
	// Unreachable absent a broken hash: a 32-byte SHA-256 digest yields a
	// valid secp256k1 scalar with overwhelming probability.
	panic(fmt.Sprintf("scenario: could not derive a valid secp256k1 scalar for %q", label))
}
