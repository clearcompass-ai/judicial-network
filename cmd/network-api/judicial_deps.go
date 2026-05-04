/*
FILE PATH: cmd/network-api/judicial_deps.go

DESCRIPTION:
    Builds the judicial.Dependencies bundle the binary feeds into
    api.Config.Judicial. Each field is satisfied by an SDK HTTP
    client, an SDK in-memory reference impl, or a JN-side reference
    impl — selected by the operational config.

    Production wiring summary
    ─────────────────────────
      OperatorEndpoint      → HTTPEntryFetcher, HTTPLeafReader,
                              one HTTPOperatorQueryAPI per registered
                              destination (per-log query API)
      ArtifactStoreEndpoint → HTTPContentStore
      EthRPCEndpoint        → not consumed here; PKHVerifier picks it
                              up at the SDK boundary
      DIDResolver           → CachingResolver(WebDIDResolver(...))
      Schema extractor      → JN schemas.Registry (knows every
                              JN schema's SchemaParameters layout)

    Things that stay in-memory until separate operational config
    arrives — surfaced clearly so a deployer knows what they are:
      ContentStore (when ArtifactStoreEndpoint is empty)
      KeyStore (AES-GCM artifact keys)
      DelKeyStore (PRE delegation keys)

    Things wired as `nil` when not configured:
      BLSVerifier    — only consumed by cross-log proof verify
      WitnessKeys    — populated by future witness-roster config
      WitnessQuorum  — same
      SourceProver   — only consumed by ops-tooling cross-log compose

    Each nil case yields a 500/501 from the specific handler that
    needs it; the rest of the surface keeps working.
*/
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/witness"

	lifecycleartifact "github.com/clearcompass-ai/ortholog-sdk/lifecycle/artifact"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
	"github.com/clearcompass-ai/judicial-network/cases/artifact"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// buildJudicialDeps composes a judicial.Dependencies for the
// supplied registry + operational config. Returns an error only on
// unrecoverable misconfiguration (e.g., OperatorEndpoint set but
// invalid). Dev / test deployments may pass an empty
// OperatorEndpoint — the deps that need it remain nil and the
// dependent handlers return 500 with a clear error.
func buildJudicialDeps(cfg config.Operational, registry *jurisdiction.Registry) (judicial.Dependencies, error) {
	deps := judicial.Dependencies{
		Registry:      registry,
		Extractor:     schemas.NewRegistry(),
		ContentStore:  newContentStore(cfg.ArtifactStoreEndpoint),
		KeyStore:      lifecycleartifact.NewInMemoryKeyStore(),
		DelKeyStore:   artifact.NewInMemoryDelegationKeyStore(),
		WitnessKeys:   map[string][]types.WitnessPublicKey{},
		WitnessQuorum: map[string]int{},
	}

	if cfg.OperatorEndpoint == "" {
		// Dev / test mode — no operator wired. Deps that need it stay
		// nil; their handlers will return 500 with a clear error.
		return deps, nil
	}

	logQueries, err := buildLogQueries(cfg.OperatorEndpoint, registry)
	if err != nil {
		return judicial.Dependencies{}, fmt.Errorf("build log queries: %w", err)
	}
	deps.LogQueries = logQueries
	deps.Fetcher = buildEntryFetcher(cfg.OperatorEndpoint)
	deps.LeafReader = buildLeafReader(cfg.OperatorEndpoint)
	deps.Resolver = buildDIDResolver()
	deps.SchemaResolver = newSchemaResolverShim()
	deps.TreeHeadClient = buildTreeHeadClient(cfg, registry)
	return deps, nil
}

// buildTreeHeadClient constructs the witness.TreeHeadClient from
// operational config. Per-destination operator endpoints override
// the top-level OperatorEndpoint; per-destination witness fallbacks
// are read from cfg.Witness.WitnessEndpoints. Empty maps fall back
// to the top-level OperatorEndpoint for every registered destination.
//
// Returns nil if cfg.OperatorEndpoint is empty (dev / test mode);
// the anchor / topology / monitoring handlers that need the client
// surface 503 in that case.
func buildTreeHeadClient(cfg config.Operational, registry *jurisdiction.Registry) *witness.TreeHeadClient {
	if cfg.OperatorEndpoint == "" {
		return nil
	}
	operators := map[string]string{}
	for _, did := range registry.ExchangeDIDs() {
		if ep, ok := cfg.Witness.OperatorEndpoints[did]; ok && ep != "" {
			operators[did] = ep
		} else {
			operators[did] = cfg.OperatorEndpoint
		}
	}
	witnesses := cfg.Witness.WitnessEndpoints
	if witnesses == nil {
		witnesses = map[string][]string{}
	}
	endpoints := &witness.StaticEndpoints{
		Operators: operators,
		Witnesses: witnesses,
	}
	thcCfg := witness.DefaultTreeHeadClientConfig()
	if cfg.Witness.CacheTTL > 0 {
		thcCfg.CacheTTL = cfg.Witness.CacheTTL
	}
	if cfg.Witness.HTTPTimeout > 0 {
		thcCfg.HTTPTimeout = cfg.Witness.HTTPTimeout
	}
	return witness.NewTreeHeadClient(endpoints, thcCfg)
}

// buildLogQueries constructs one HTTPOperatorQueryAPI per registered
// destination. The map is keyed by destination DID so judicial
// handlers can route per-destination read queries (case lookup,
// docket scan) to the right log.
func buildLogQueries(operatorEndpoint string, registry *jurisdiction.Registry) (map[string]sdklog.OperatorQueryAPI, error) {
	out := make(map[string]sdklog.OperatorQueryAPI, registry.Len())
	for _, didStr := range registry.ExchangeDIDs() {
		q, err := sdklog.NewHTTPOperatorQueryAPI(sdklog.HTTPOperatorQueryAPIConfig{
			BaseURL: operatorEndpoint,
			LogDID:  didStr,
		})
		if err != nil {
			return nil, fmt.Errorf("query api for %s: %w", didStr, err)
		}
		out[didStr] = q
	}
	return out, nil
}

func buildEntryFetcher(operatorEndpoint string) types.EntryFetcher {
	return sdklog.NewHTTPEntryFetcher(sdklog.HTTPEntryFetcherConfig{
		BaseURL: operatorEndpoint,
	})
}

func buildLeafReader(operatorEndpoint string) smt.LeafReader {
	return smt.NewHTTPLeafReader(smt.HTTPLeafReaderConfig{
		BaseURL: operatorEndpoint,
	})
}

// buildDIDResolver returns a caching WebDIDResolver. did:web is the
// only method JN handlers resolve at runtime; did:pkh and did:key
// are address/key based and need no Resolve() call. The cache
// shaves the resolver hot-path to ~zero on warm runs.
func buildDIDResolver() did.DIDResolver {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	web := did.NewWebDIDResolver(httpClient)
	return did.NewCachingResolver(web, 5*time.Minute)
}

// newContentStore returns an HTTP content store when the artifact
// store endpoint is configured, falling back to an in-memory store
// for dev / test. Either way the interface contract is identical;
// only the backend differs.
func newContentStore(endpoint string) storage.ContentStore {
	if endpoint == "" {
		return storage.NewInMemoryContentStore()
	}
	return storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{
		BaseURL: endpoint,
	})
}

// schemaResolverShim returns a non-nil builder.SchemaResolver that
// declines every lookup. Production deployments wire a real resolver
// against the schemas-log; the shim keeps the binary boot-clean
// until that wiring lands.
type schemaResolverShim struct{}

func newSchemaResolverShim() builder.SchemaResolver { return schemaResolverShim{} }

func (schemaResolverShim) Resolve(_ types.LogPosition, _ types.EntryFetcher) (*types.SchemaResolution, error) {
	return nil, fmt.Errorf("schema resolver not configured (boot-time shim — wire schemas-log resolver in production)")
}
