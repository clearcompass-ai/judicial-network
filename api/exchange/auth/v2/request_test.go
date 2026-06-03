package v2

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	sdkauth "github.com/baseproof/baseproof/exchange/auth"
)

// validEnvelope returns a SignedRequestEnvelope that passes the
// SDK's validateFields() so SigningBytes can canonicalize cleanly.
func validEnvelope(now time.Time) sdkauth.SignedRequestEnvelope {
	return sdkauth.SignedRequestEnvelope{
		Version:   sdkauth.EnvelopeVersion,
		DID:       "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		Domain:    "api.example.com",
		Nonce:     "nonce-request-test",
		Method:    "POST",
		Path:      "/v1/judicial/case",
		IssuedAt:  now.Add(-1 * time.Second),
		ExpiresAt: now.Add(30 * time.Second),
	}
}

// TestSigningBytes_ContainsSDKCanonicalAsPrefix is the load-bearing
// security pin from the doc.go contract: the SDK canonical MUST
// appear verbatim as a prefix of the v2 SigningBytes. Without
// this, a forger could produce a colliding extension that the SDK
// envelope's identity invariants don't cover.
func TestSigningBytes_ContainsSDKCanonicalAsPrefix(t *testing.T) {
	env := validEnvelope(time.Now().UTC().Truncate(time.Second))
	req := &Request{Envelope: env, Action: "create_filing"}

	signed, err := req.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	sdkCanon, err := env.Canonicalize()
	if err != nil {
		t.Fatalf("env.Canonicalize: %v", err)
	}

	if len(signed) <= len(sdkCanon) {
		t.Fatalf("signed bytes not strictly larger than SDK canonical (%d vs %d)",
			len(signed), len(sdkCanon))
	}
	if string(signed[:len(sdkCanon)]) != string(sdkCanon) {
		t.Fatal("SDK canonical is not a prefix of SigningBytes")
	}
}

// TestSigningBytes_ActionLengthPrefixed pins the length-prefixed
// layout: the bytes after the SDK canonical are u32_be(len(action))
// || action_bytes.
func TestSigningBytes_ActionLengthPrefixed(t *testing.T) {
	env := validEnvelope(time.Now().UTC().Truncate(time.Second))
	req := &Request{Envelope: env, Action: "create_filing"}

	signed, _ := req.SigningBytes()
	sdkCanon, _ := env.Canonicalize()

	rest := signed[len(sdkCanon):]
	if len(rest) < 4 {
		t.Fatalf("rest too short for length prefix: %d", len(rest))
	}
	actionLen := binary.BigEndian.Uint32(rest[:4])
	if int(actionLen) != len(req.Action) {
		t.Fatalf("action length prefix = %d, want %d", actionLen, len(req.Action))
	}
	if string(rest[4:4+actionLen]) != req.Action {
		t.Fatalf("action bytes = %q, want %q", rest[4:4+actionLen], req.Action)
	}
}

// TestSigningBytes_EmptyDestinationStillEncoded pins the security
// property that an empty Destination is signed-bound just like a
// non-empty one — a four-byte zero-length prefix. Defeats "drop
// the destination from the suffix to forge a different routing
// posture" attacks.
func TestSigningBytes_EmptyDestinationStillEncoded(t *testing.T) {
	env := validEnvelope(time.Now().UTC().Truncate(time.Second))
	req := &Request{Envelope: env, Action: "create_filing", Destination: ""}

	signed, err := req.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	sdkCanon, _ := env.Canonicalize()
	rest := signed[len(sdkCanon):]
	// rest layout: [actionLen u32][action bytes][destLen u32][dest bytes]
	actionLen := binary.BigEndian.Uint32(rest[:4])
	destOffset := 4 + int(actionLen)
	if len(rest) < destOffset+4 {
		t.Fatalf("missing destination length prefix; rest len=%d, expected >=%d",
			len(rest), destOffset+4)
	}
	destLen := binary.BigEndian.Uint32(rest[destOffset : destOffset+4])
	if destLen != 0 {
		t.Fatalf("destLen = %d, want 0 for empty Destination", destLen)
	}
	// Total length must be exactly destOffset+4 (no trailing bytes).
	if len(rest) != destOffset+4 {
		t.Fatalf("trailing bytes after empty Destination: %d extra", len(rest)-destOffset-4)
	}
}

// TestSigningBytes_DestinationChangeChangesBytes pins the security
// property the pre-v2 test suite pinned: changing Destination
// after signing changes the bytes — so a swap-replay attempt
// produces a different hash and signature verification fails.
func TestSigningBytes_DestinationChangeChangesBytes(t *testing.T) {
	env := validEnvelope(time.Now().UTC().Truncate(time.Second))
	a := &Request{Envelope: env, Action: "create_filing", Destination: "did:web:exch:davidson"}
	b := &Request{Envelope: env, Action: "create_filing", Destination: "did:web:exch:shelby"}

	aBytes, _ := a.SigningBytes()
	bBytes, _ := b.SigningBytes()
	if string(aBytes) == string(bBytes) {
		t.Fatal("SigningBytes equal across distinct Destinations; swap-replay would succeed")
	}
}

// TestSigningBytes_ActionChangeChangesBytes is the companion pin
// for Action.
func TestSigningBytes_ActionChangeChangesBytes(t *testing.T) {
	env := validEnvelope(time.Now().UTC().Truncate(time.Second))
	a := &Request{Envelope: env, Action: "create_filing"}
	b := &Request{Envelope: env, Action: "amend_filing"}

	aBytes, _ := a.SigningBytes()
	bBytes, _ := b.SigningBytes()
	if string(aBytes) == string(bBytes) {
		t.Fatal("SigningBytes equal across distinct Actions; cross-endpoint replay would succeed")
	}
}

// TestSigningBytes_RejectsEmptyAction pins the JN-domain
// requirement that every v2 Request carry a named Action.
func TestSigningBytes_RejectsEmptyAction(t *testing.T) {
	env := validEnvelope(time.Now().UTC().Truncate(time.Second))
	req := &Request{Envelope: env, Action: ""}

	_, err := req.SigningBytes()
	if err == nil {
		t.Fatal("want error on empty Action, got nil")
	}
	if !strings.Contains(err.Error(), "Action") {
		t.Errorf("error must mention Action: %v", err)
	}
}

// TestSigningBytes_Deterministic pins that identical Requests
// produce identical signing bytes. This is the SDK's
// canonicalization contract surfaced at the JN extension layer.
func TestSigningBytes_Deterministic(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	env := validEnvelope(now)
	req := &Request{Envelope: env, Action: "create_filing", Destination: "did:web:exch:davidson"}

	first, _ := req.SigningBytes()
	second, _ := req.SigningBytes()
	if string(first) != string(second) {
		t.Fatal("SigningBytes not deterministic for identical inputs")
	}
}
