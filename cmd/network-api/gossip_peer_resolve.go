/*
FILE PATH: cmd/network-api/gossip_peer_resolve.go

DESCRIPTION:

	did:web resolution for gossip-ingest peer bases — parity with the auditor's
	AUDITOR_PEERS did:web form.

	A gossip peer's BaseURL may be given as a bare did:web (in
	API_GOSSIP_INGEST_PEER_URL or a Peers[].BaseURL) instead of an http(s) URL.
	At boot the binary resolves it ONCE to the ledger's gossip base from the DID
	document's AttestaLedger service endpoint, using the SAME SDK mechanism the
	auditor uses: did.DIDEndpointAdapter over a TTL-cached WebDIDResolver
	(attesta v1.24.0). An http(s) BaseURL is used verbatim — resolution is
	bypassed.

	WHY "once, at the right layer" (not per-call through ResolvingCheckpointClient):
	the gossip puller's feed (/v1/gossip/since) is URL-addressed and needs the
	resolved base regardless, so a single up-front resolution keeps the peer on
	one consistent endpoint. The DID-addressed horizon path (anchor publishing)
	stays on ResolvingCheckpointClient, where nothing else needs the URL.

	FAILS CLOSED: a did:web base with no resolver, an unresolvable DID, or a DID
	document without an AttestaLedger endpoint errors at boot rather than starting
	an ingest loop pointed nowhere. The LogDID (originator, the witness-set
	routing key) is untouched — it continues to come from /v1/log-info discovery
	or config; only the byte-source BaseURL is resolved here.
*/
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/clearcompass-ai/attesta/did"

	"github.com/clearcompass-ai/judicial-network/api/config"
)

// defaultDIDWebTTL is the WebDIDResolver cache TTL applied when
// GossipIngest.DIDWebTTL is unset. Matches the auditor's AUDITOR_DIDWEB_TTL
// default (5m): long enough to amortise repeated boots, short enough that a
// peer's endpoint rotation propagates within the window.
const defaultDIDWebTTL = 5 * time.Minute

// peerEndpointResolver resolves a did:web to its AttestaLedger service endpoint.
// did.DIDEndpointAdapter satisfies it; tests inject a fake (no network).
type peerEndpointResolver interface {
	LedgerEndpoint(ctx context.Context, didWeb string) (string, error)
}

// resolveGossipPeerEndpoints rewrites any peer whose BaseURL is a bare did:web
// into its resolved AttestaLedger endpoint. http(s) bases pass through. The
// returned slice is a copy — the input is not mutated. Fails closed on a
// did:web base with a nil resolver, a resolve error, or an empty endpoint.
func resolveGossipPeerEndpoints(ctx context.Context, peers []config.GossipPeerConfig, resolver peerEndpointResolver) ([]config.GossipPeerConfig, error) {
	out := make([]config.GossipPeerConfig, len(peers))
	copy(out, peers)
	for i := range out {
		base := out[i].BaseURL
		if !isDIDWeb(base) {
			continue
		}
		if resolver == nil {
			return nil, fmt.Errorf("gossip peer base %q is a did:web but no resolver is configured", base)
		}
		url, err := resolver.LedgerEndpoint(ctx, base)
		if err != nil {
			return nil, fmt.Errorf("resolve did:web peer base %q: %w", base, err)
		}
		if url == "" {
			return nil, fmt.Errorf("did:web peer base %q resolved to an empty AttestaLedger endpoint", base)
		}
		out[i].BaseURL = url
	}
	return out, nil
}

// isDIDWeb reports whether s is a did:web identifier (vs an http(s) URL).
func isDIDWeb(s string) bool {
	return strings.HasPrefix(s, "did:web:")
}

// newDIDWebPeerResolver builds the TTL-cached did:web → AttestaLedger resolver:
// did.DIDEndpointAdapter over a CachingResolver(WebDIDResolver). ttl <= 0 →
// defaultDIDWebTTL.
func newDIDWebPeerResolver(ttl time.Duration) *did.DIDEndpointAdapter {
	if ttl <= 0 {
		ttl = defaultDIDWebTTL
	}
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	// SDK v1.27.0: NewWebDIDResolver takes a config struct + returns (*resolver, error).
	// On construction failure we fall back to a plain caching resolver around a
	// stub so the gossip path degrades to "no peer endpoints resolved" rather
	// than crashing the binary. (Cfg.Client is non-nil here, so this can't fail
	// in practice — defensive.)
	web, err := did.NewWebDIDResolver(did.WebDIDResolverConfig{Client: httpClient})
	if err != nil {
		slog.Warn("jn/gossip: web DID resolver construction failed", "error", err)
		return nil
	}
	return &did.DIDEndpointAdapter{Resolver: did.NewCachingResolver(web, ttl)}
}
