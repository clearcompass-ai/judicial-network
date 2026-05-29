/*
FILE PATH:

	api/exchange/auth/v2/request.go

DESCRIPTION:

	Request is the v2 signed-request wire shape. The SDK envelope
	provides the cryptographic + replay-defense skeleton; this
	package adds two JN-specific length-prefixed extensions —
	Action and Destination — that bind the request to a symbolic
	domain action and a tenant routing key respectively.

CANONICAL BYTES (the bytes a DID-controlled key signs)

	sdk_canonical_bytes
	  || u32_be(len(action)) || action_bytes
	  || u32_be(len(destination)) || destination_bytes

	The SDK canonical comes first (so future SDK envelope growth
	cannot collide with the JN extension), and each extension field
	is unambiguously length-prefixed (so an empty Destination is
	indistinguishable from a missing Destination — both produce a
	four-byte zero-length prefix, defeating "drop the suffix" trickery).
*/
package v2

import (
	"encoding/binary"
	"fmt"

	sdkauth "github.com/clearcompass-ai/attesta/exchange/auth"
)

// Request is the v2 signed-request envelope. The Envelope field is
// the SDK shape verbatim; Action and Destination are the JN
// extension bytes.
type Request struct {
	// Envelope is the SDK's SignedRequestEnvelope — DID, Domain,
	// ChainID, Nonce, IssuedAt, ExpiresAt, Method, Path, BodyHash.
	// Every SDK security gate (validity window, clock skew, domain
	// match, field hygiene) is applied to this envelope unchanged.
	Envelope sdkauth.SignedRequestEnvelope `json:"envelope"`

	// Action is the JN symbolic operation name (e.g.,
	// "create_filing", "amend_case"). Signature-bound. Required.
	Action string `json:"action"`

	// Destination is the JN tenant routing key (e.g.,
	// "did:web:exch:davidson"). When non-empty, the SignerAuth
	// middleware uses it to route the nonce reservation to a
	// per-tenant NonceStore namespace, defeating swap-replay
	// across tenants. The empty-Destination case is the single-
	// tenant fallback. Signature-bound either way (an empty
	// Destination produces a four-byte zero-length prefix in
	// SigningBytes, distinct from a non-empty one).
	Destination string `json:"destination,omitempty"`

	// Signature is the DID-controlled key's signature over
	// SigningBytes(). Algorithm is selected by Envelope's AlgoID
	// at verify time via the SDK VerifierRegistry.
	Signature []byte `json:"signature"`
}

// SigningBytes returns the exact byte sequence the DID-controlled
// signing key signed. The shape:
//
//	sdk_canonical_bytes
//	  || u32_be(len(action)) || action_bytes
//	  || u32_be(len(destination)) || destination_bytes
//
// Callers MUST treat this as a black box: it is the input to the
// SDK's signature-verification primitive via
// VerifyRequestOptions.CanonicalBytes.
func (r *Request) SigningBytes() ([]byte, error) {
	if r.Action == "" {
		return nil, fmt.Errorf("auth/v2: empty Action (the JN domain demands a named operation)")
	}
	sdkBytes, err := r.Envelope.Canonicalize()
	if err != nil {
		return nil, fmt.Errorf("auth/v2: SDK envelope canonicalize: %w", err)
	}
	out := make([]byte, 0, len(sdkBytes)+8+len(r.Action)+len(r.Destination))
	out = append(out, sdkBytes...)
	out = appendLengthPrefixed(out, []byte(r.Action))
	out = appendLengthPrefixed(out, []byte(r.Destination))
	return out, nil
}

// appendLengthPrefixed appends a u32-big-endian length followed by
// the bytes themselves. Empty input produces a four-byte zero-
// length prefix — that's the load-bearing property that makes
// "missing Destination" and "empty Destination" distinguishable
// from "Destination dropped from the suffix."
func appendLengthPrefixed(dst, b []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, b...)
}
