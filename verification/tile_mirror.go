// FILE PATH: verification/tile_mirror.go
//
// DESCRIPTION:
//
//	HTTPTileMirrors resolves a source-log DID to a Static-CT tile fetcher
//	pointed at that log's tile mirror, satisfying TileFetcherSource for the
//	gossip verifier's ClassMerkle (cross-log inclusion) path.
//
//	ZERO-TRUST NOTE: a tile mirror need not be trusted. A cross-log inclusion
//	proof is RFC 6962-verified against the TRUSTED source head's RootHash (from
//	the TrustedHeadStore, advanced only by verified CosignedTreeHeads); a mirror
//	serving wrong tiles yields a proof that fails the root check. The mirror is
//	a data source; the head is the trust anchor. Mirrors are still operator-
//	pinned (allowlist) to bound where JN issues fetches.
package verification

import (
	"fmt"
	"net/http"
	"net/url"

	tessera "github.com/transparency-dev/tessera/client"
)

// HTTPTileMirrors maps source-log DID → Static-CT tile fetcher. Immutable after
// construction; safe for concurrent use.
type HTTPTileMirrors struct {
	fetchers map[string]tessera.TileFetcherFunc
}

// NewHTTPTileMirrors builds a resolver from a source-log-DID → tile-root-URL
// map. Each URL is wrapped in the SDK's tessera HTTPFetcher; its ReadTile method
// is the TileFetcherFunc. An empty map yields a resolver that resolves nothing
// (every merkle finding then fails-closed). hc nil ⇒ http.DefaultClient.
func NewHTTPTileMirrors(mirrors map[string]string, hc *http.Client) (*HTTPTileMirrors, error) {
	out := make(map[string]tessera.TileFetcherFunc, len(mirrors))
	for logDID, rawURL := range mirrors {
		if logDID == "" {
			return nil, fmt.Errorf("verification/tile_mirror: empty log DID")
		}
		if rawURL == "" {
			return nil, fmt.Errorf("verification/tile_mirror: empty tile URL for %q", logDID)
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("verification/tile_mirror: parse URL for %q: %w", logDID, err)
		}
		f, err := tessera.NewHTTPFetcher(u, hc)
		if err != nil {
			return nil, fmt.Errorf("verification/tile_mirror: fetcher for %q: %w", logDID, err)
		}
		out[logDID] = f.ReadTile
	}
	return &HTTPTileMirrors{fetchers: out}, nil
}

// FetcherFor returns the tile fetcher for sourceLogDID, or (nil, false) if no
// mirror is configured for it.
func (m *HTTPTileMirrors) FetcherFor(sourceLogDID string) (tessera.TileFetcherFunc, bool) {
	f, ok := m.fetchers[sourceLogDID]
	return f, ok
}
