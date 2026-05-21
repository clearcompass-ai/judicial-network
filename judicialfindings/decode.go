// FILE PATH: judicialfindings/decode.go
//
// DESCRIPTION:
//
//	DecodeWireBody is the inbound counterpart to the router: it turns a
//	gossip wire body (Kind + raw JSON, as pulled from a peer feed) into the
//	typed, in-memory finding (a gossip.Event) that Verify then dispatches.
//	It composes the SDK's per-Kind wire decoder (gossip.DecodeWireBody) with
//	the gossip/findings factories, so the ENTIRE event dictionary is decoded
//	in the same package that classifies (Registry) and verifies (Router) it —
//	"add a Kind" stays a one-package change.
//
//	Fail-closed: an unregistered Kind (gossip.ErrUnknownKind) or a malformed
//	body (gossip.ErrInvalidWireRequest) returns an error and never a partially
//	decoded finding. A pulled event is attacker-controlled bytes until it has
//	passed BOTH this decode and the router's cryptographic Verify.
package judicialfindings

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
)

// ErrDecode wraps every wire-decode failure. The underlying SDK sentinels
// (gossip.ErrUnknownKind, gossip.ErrInvalidWireRequest) are reachable via
// errors.Is.
var ErrDecode = errors.New("judicialfindings/decode")

// DecodeWireBody parses (kind, raw) into the matching typed finding. The
// returned gossip.Event is UNVERIFIED — the caller MUST run Verify before
// acting on it.
func DecodeWireBody(kind gossip.Kind, raw json.RawMessage) (gossip.Event, error) {
	body, err := gossip.DecodeWireBody(kind, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecode, err)
	}
	switch w := body.(type) {
	case gossip.WireCosignedTreeHeadBody:
		return decoded(findings.CosignedTreeHeadFromWire(w))
	case gossip.WireEquivocationFinding:
		return decoded(findings.EquivocationFromWire(w))
	case gossip.WireEscrowOverrideAuth:
		return decoded(findings.EscrowOverrideFromWire(w))
	case gossip.WireOriginatorRotation:
		return decoded(findings.OriginatorRotationFromWire(w))
	case gossip.WireEntryCommitmentEquivocationBody:
		return decoded(findings.EntryCommitmentEquivocationFromWire(w))
	case gossip.WireGhostLeafBody:
		return decoded(findings.FromWireGhostLeaf(w))
	case gossip.WireWitnessRotationBody:
		return decoded(findings.WitnessRotationFromWire(w))
	case gossip.WireCrossLogInclusionBody:
		return decoded(findings.FromWireCrossLogInclusion(w))
	default:
		// gossip.DecodeWireBody admitted a registered Kind whose wire type
		// has no JN factory — an SDK addition that outran this dispatch.
		return nil, fmt.Errorf("%w: no finding factory for wire type %T (kind %q)", ErrDecode, w, kind)
	}
}

// decoded normalises a findings factory result: on error it returns an
// ErrDecode-wrapped error and an explicit nil interface (never a non-nil
// gossip.Event wrapping a typed-nil pointer); on success it returns the
// finding as gossip.Event.
func decoded[T gossip.Event](f T, err error) (gossip.Event, error) {
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecode, err)
	}
	return f, nil
}
