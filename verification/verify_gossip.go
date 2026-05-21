// FILE PATH: verification/verify_gossip.go
//
// DESCRIPTION:
//
//	GossipVerifier is the zero-trust verification seam for INBOUND gossip
//	events pulled from peer ledgers. Every pulled event is attacker-controlled
//	bytes until it passes the two-tier check here; only then may a downstream
//	enforcer act on it or JN re-serve it.
//
//	  Tier 1 — Envelope authenticity (gossip.Verify): the originator actually
//	    signed THIS event for THIS network. A pulling client receives raw JSON,
//	    so JN performs this itself — the SDK server does it on push; the puller
//	    is its own gossip layer. This is the authority for self-attested Kinds
//	    (originator/ghost) and the transport-identity check for all others.
//
//	  Tier 2 — Finding proof (judicialfindings.Router): the embedded K-of-N /
//	    signer / merkle proof, dispatched by Kind against JN-LOCAL trust roots
//	    only — witness sets from the registry, JN's own SignerVerifier, a
//	    trusted tile mirror. A finding's self-claimed identifiers are lookup
//	    keys into local trust, never trust themselves.
//
//	Fail-closed: any failure returns an error and no event.
package verification

import (
	"context"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
	tessera "github.com/transparency-dev/tessera/client"

	"github.com/clearcompass-ai/judicial-network/judicialfindings"
)

// ErrGossipVerify wraps every inbound-event verification failure. Underlying
// SDK + router sentinels are reachable via errors.Is.
var ErrGossipVerify = errors.New("verification/verify_gossip")

// EnvelopeVerifier authenticates a gossip SignedEvent's originator signature
// (Tier 1). The production implementation delegates to gossip.Verify; it is an
// interface so tests can exercise JN's decode+route wiring without minting a
// full cosign envelope.
type EnvelopeVerifier interface {
	VerifyEnvelope(ctx context.Context, ev gossip.SignedEvent) error
}

// gossipEnvelopeVerifier is the production EnvelopeVerifier: gossip.Verify with
// a DID-backed OriginatorVerifier bound to the network's NetworkID.
type gossipEnvelopeVerifier struct {
	originator gossip.OriginatorVerifier
	networkID  cosign.NetworkID
}

func (g gossipEnvelopeVerifier) VerifyEnvelope(ctx context.Context, ev gossip.SignedEvent) error {
	return gossip.Verify(ctx, ev, g.originator, g.networkID)
}

// TreeHeadSource resolves the JN-trusted source tree head for a source-log DID,
// the trust anchor for ClassMerkle (cross-log inclusion) proof replay. A nil
// source ⇒ merkle findings cannot be verified and the router returns its
// missing-dependency error (fail-closed). monitoring.TrustedHeadStore satisfies
// it — JN's view of each peer log's head, advanced only by verified
// CosignedTreeHeads.
type TreeHeadSource interface {
	TrustedHead(sourceLogDID string) (types.TreeHead, bool)
}

// TileFetcherSource resolves a Static-CT tile fetcher for a source-log DID. The
// fetcher need not be trusted: a cross-log inclusion proof is RFC 6962-checked
// against the TRUSTED source head's RootHash, so wrong tiles produce a proof
// that fails the root check. The security anchor is the head (from
// TreeHeadSource), not the mirror. Unknown DID ⇒ (nil, false) ⇒ the merkle
// finding fails-closed at the router.
type TileFetcherSource interface {
	FetcherFor(sourceLogDID string) (tessera.TileFetcherFunc, bool)
}

// GossipVerifier runs the two-tier check. Construct via NewGossipVerifier;
// safe for concurrent use (the witness-set registry is concurrency-safe and
// every other field is read-only after construction).
type GossipVerifier struct {
	envelope EnvelopeVerifier
	sets     *WitnessSetRegistry
	signer   findings.SignerVerifier
	heads    TreeHeadSource
	tiles    TileFetcherSource
}

// GossipVerifierConfig configures a GossipVerifier.
type GossipVerifierConfig struct {
	// Originator + NetworkID build the default envelope verifier (gossip.Verify).
	// Required unless Envelope is supplied directly.
	Originator gossip.OriginatorVerifier
	NetworkID  cosign.NetworkID

	// Envelope overrides the default gossip.Verify-backed envelope check
	// (test injection). When nil, Originator + NetworkID are used.
	Envelope EnvelopeVerifier

	// WitnessSets is the live, monotonic witness-set registry. Required —
	// it is the trust root for every ClassWitness finding.
	WitnessSets *WitnessSetRegistry

	// SignerVerifier verifies ClassSigner findings (typically a
	// *did.VerifierRegistry). Optional; absent ⇒ signer findings fail-closed.
	SignerVerifier findings.SignerVerifier

	// Heads + Tiles enable ClassMerkle (cross-log inclusion). Both keyed by the
	// finding's own SourceLogDID. Optional; absent ⇒ merkle findings fail-closed
	// via the router's missing-dependency error.
	Heads TreeHeadSource
	Tiles TileFetcherSource
}

// NewGossipVerifier validates config and returns a GossipVerifier.
func NewGossipVerifier(cfg GossipVerifierConfig) (*GossipVerifier, error) {
	if cfg.WitnessSets == nil {
		return nil, fmt.Errorf("%w: nil WitnessSets registry", ErrGossipVerify)
	}
	env := cfg.Envelope
	if env == nil {
		if cfg.Originator == nil {
			return nil, fmt.Errorf("%w: nil Originator verifier (or supply Envelope)", ErrGossipVerify)
		}
		if cfg.NetworkID.IsZero() {
			return nil, fmt.Errorf("%w: zero NetworkID", ErrGossipVerify)
		}
		env = gossipEnvelopeVerifier{originator: cfg.Originator, networkID: cfg.NetworkID}
	}
	return &GossipVerifier{
		envelope: env,
		sets:     cfg.WitnessSets,
		signer:   cfg.SignerVerifier,
		heads:    cfg.Heads,
		tiles:    cfg.Tiles,
	}, nil
}

// Verify runs Tier 1 (envelope) → decode → Tier 2 (finding proof) and returns
// the decoded, verified finding. A non-nil error means the event MUST be
// discarded — never acted on, never re-served.
//
// SourceLogDID is set to the envelope originator: correct for the originator-
// is-source Kinds (cosigned tree head, escrow override, witness rotation) and
// irrelevant to self-attested / signer / merkle Kinds. Equivocation findings
// whose reporter differs from the equivocating log are a documented follow-up
// (the SDK proof does not expose the target log as a DID).
func (gv *GossipVerifier) Verify(ctx context.Context, ev gossip.SignedEvent) (gossip.Event, error) {
	// Tier 1: envelope authenticity.
	if err := gv.envelope.VerifyEnvelope(ctx, ev); err != nil {
		return nil, fmt.Errorf("%w: envelope: %w", ErrGossipVerify, err)
	}
	// Decode the body into a typed finding (fail-closed on unknown/malformed).
	event, err := judicialfindings.DecodeWireBody(ev.Kind, ev.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGossipVerify, err)
	}
	// Tier 2: finding proof against LOCAL trust roots.
	vc := judicialfindings.VerificationContext{
		SourceLogDID:   ev.Originator,
		WitnessSets:    gv.sets.Snapshot(),
		SignerVerifier: gv.signer,
	}
	// ClassMerkle (cross-log inclusion) anchors on the SOURCE log named INSIDE
	// the finding — which may differ from the gossip originator that relayed
	// it. Resolve the trusted head + tile fetcher by the finding's own
	// SourceLogDID so a relayed attestation is checked against the source log
	// JN independently trusts, not against the relayer.
	if cli, ok := event.(*findings.CrossLogInclusionFinding); ok {
		if gv.heads != nil {
			if head, ok := gv.heads.TrustedHead(cli.SourceLogDID); ok {
				vc.SourceHead = head
			}
		}
		if gv.tiles != nil {
			if fetcher, ok := gv.tiles.FetcherFor(cli.SourceLogDID); ok {
				vc.TileFetcher = fetcher
			}
		}
	}
	if err := judicialfindings.Verify(ctx, event, vc); err != nil {
		return nil, fmt.Errorf("%w: finding: %w", ErrGossipVerify, err)
	}
	return event, nil
}
