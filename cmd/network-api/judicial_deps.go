/*
FILE PATH: cmd/network-api/judicial_deps.go

DESCRIPTION:

	Builds the judicial.Dependencies bundle the binary feeds into
	api.Config.Judicial. Each field is satisfied by an SDK HTTP
	client, an SDK in-memory reference impl, or a JN-side reference
	impl — selected by the operational config.

	Production wiring summary
	─────────────────────────
	  LedgerEndpoint      → HTTPEntryFetcher, HTTPLeafReader,
	                          one HTTPLedgerQueryAPI per registered
	                          destination (per-log query API)
	  ArtifactStoreEndpoint → HTTPContentStore
	  SmartContractWallet   → per-chain PKHVerifier quorums routed by
	                          did.MultiChainPKHVerifier; built in
	                          signature_verifier.go, wired into the
	                          verification service's SignatureVerifier
	  DIDResolver           → CachingResolver(VendorDIDResolver(
	                          MethodRouter{web, key, pkh}, JN vendor mappings))
	  Schema extractor      → JN schemas.Registry (knows every
	                          JN schema's SchemaParameters layout)

	Things that stay in-memory until separate operational config
	arrives — surfaced clearly so a deployer knows what they are:
	  ContentStore (when ArtifactStoreEndpoint is empty)
	  KeyStore (AES-GCM artifact keys)
	  DelKeyStore (PRE delegation keys)

	Things wired as empty when not configured:
	  WitnessSets   — per-log witness topology (keys + K + NetworkID +
	                  BLSVerifier together inside *cosign.WitnessKeySet).
	                  Empty map → handlers that need it return 503.
	  SourceProver  — only consumed by ops-tooling cross-log compose

	Each nil case yields a 500/501 from the specific handler that
	needs it; the rest of the surface keeps working.

	v0.3.0: SDK Principle 10 (Two-Tier Quorum Encapsulation) replaces
	the legacy WitnessKeys / WitnessQuorum / WitnessNetwork trio with
	a single map[string]*cosign.WitnessKeySet. The constructor
	(cosign.NewWitnessKeySet) catches duplicate IDs, zero NetworkID,
	and K outside [1, N] at boot — failures that previously surfaced
	at HTTP-request time.
*/
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/clearcompass-ai/attesta/builder"
	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/did"
	sdklog "github.com/clearcompass-ai/attesta/log"
	sdknetwork "github.com/clearcompass-ai/attesta/network"
	"github.com/clearcompass-ai/attesta/storage"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/witness"

	lifecycleartifact "github.com/clearcompass-ai/attesta/lifecycle/artifact"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
	"github.com/clearcompass-ai/judicial-network/cases/artifact"
	"github.com/clearcompass-ai/judicial-network/crosslog"
	judicialdid "github.com/clearcompass-ai/judicial-network/did"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// buildJudicialDeps composes a judicial.Dependencies for the
// supplied registry + operational config. Returns an error only on
// unrecoverable misconfiguration (e.g., LedgerEndpoint set but
// invalid). Dev / test deployments may pass an empty
// LedgerEndpoint — the deps that need it remain nil and the
// dependent handlers return 500 with a clear error.
func buildJudicialDeps(cfg config.Operational, registry *jurisdiction.Registry) (judicial.Dependencies, error) {
	witnessSets, err := buildWitnessSets(cfg)
	if err != nil {
		return judicial.Dependencies{}, fmt.Errorf("build witness sets: %w", err)
	}

	deps := judicial.Dependencies{
		Registry:     registry,
		Extractor:    schemas.NewRegistry(),
		ContentStore: newContentStore(cfg.ArtifactStoreEndpoint),
		KeyStore:     lifecycleartifact.NewInMemoryKeyStore(),
		DelKeyStore:  artifact.NewInMemoryDelegationKeyStore(),
		// One *cosign.WitnessKeySet per source/peer log DID, resolved from
		// cfg.Witness.Sets against the network's NetworkID. Empty when no
		// sets are configured → cross-log handlers surface 503 with a clear
		// "no witness set for source_log_did" error.
		WitnessSets: witnessSets,
	}

	if cfg.LedgerEndpoint == "" {
		// Dev / test mode — no ledger wired. Deps that need it stay
		// nil; their handlers will return 500 with a clear error.
		return deps, nil
	}

	logQueries, err := buildLogQueries(cfg.LedgerEndpoint, registry)
	if err != nil {
		return judicial.Dependencies{}, fmt.Errorf("build log queries: %w", err)
	}
	deps.LogQueries = logQueries
	deps.Fetcher = buildEntryFetcher(cfg.LedgerEndpoint)
	deps.LeafReader = buildLeafReader(cfg.LedgerEndpoint)
	resolver, err := buildDIDResolver()
	if err != nil {
		return judicial.Dependencies{}, fmt.Errorf("build DID resolver: %w", err)
	}
	deps.Resolver = resolver
	deps.SchemaResolver = newSchemaResolverShim()
	deps.TreeHeadClient = buildTreeHeadClient(cfg, registry)
	return deps, nil
}

// buildWitnessSets resolves cfg.Witness.Sets into the per-source-log
// *cosign.WitnessKeySet map that the cross-log verification paths read
// (VerifyCrossLogProof, crosslog.VerifyCosignedAnchor).
//
// No sets configured → an empty (non-nil) map; cross-log handlers then
// surface 503 for an unknown source log. When sets ARE configured the
// network identity is mandatory: each keyset binds to the cosign
// NetworkID derived from cfg.NetworkBootstrapFile, so an empty bootstrap
// path is a boot-failing misconfiguration (a zero NetworkID would make
// every cross-log cosignature verification fail at request time).
func buildWitnessSets(cfg config.Operational) (map[string]*cosign.WitnessKeySet, error) {
	if len(cfg.Witness.Sets) == 0 {
		return map[string]*cosign.WitnessKeySet{}, nil
	}
	if cfg.NetworkBootstrapFile == "" {
		return nil, fmt.Errorf("witness sets configured but NetworkBootstrapFile is empty (cross-log keysets need the network ID)")
	}
	networkID, err := loadNetworkID(cfg.NetworkBootstrapFile)
	if err != nil {
		return nil, fmt.Errorf("load network id: %w", err)
	}
	return crosslog.BuildWitnessSets(cfg.Witness.Sets, networkID)
}

// loadNetworkID reads the bootstrap document from disk, parses it,
// and derives the 32-byte cosign NetworkID. Boot fails fast on any
// error — a misconfigured bootstrap document means cross-component
// cosignature verification cannot succeed, and every dependent
// handler would return 500 at runtime.
func loadNetworkID(path string) (cosign.NetworkID, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return cosign.NetworkID{}, fmt.Errorf("read %s: %w", path, err)
	}
	var doc sdknetwork.BootstrapDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return cosign.NetworkID{}, fmt.Errorf("parse %s: %w", path, err)
	}
	ids, err := doc.IDs()
	if err != nil {
		return cosign.NetworkID{}, fmt.Errorf("derive network identity from %s: %w", path, err)
	}
	return ids.NetworkID, nil
}

// buildTreeHeadClient constructs the witness.TreeHeadClient from
// operational config. Per-destination ledger endpoints override
// the top-level LedgerEndpoint; per-destination witness fallbacks
// are read from cfg.Witness.WitnessEndpoints. Empty maps fall back
// to the top-level LedgerEndpoint for every registered destination.
//
// Returns nil if cfg.LedgerEndpoint is empty (dev / test mode);
// the anchor / topology / monitoring handlers that need the client
// surface 503 in that case.
func buildTreeHeadClient(cfg config.Operational, registry *jurisdiction.Registry) *witness.TreeHeadClient {
	if cfg.LedgerEndpoint == "" {
		return nil
	}
	ledgers := map[string]string{}
	for _, did := range registry.ExchangeDIDs() {
		if ep, ok := cfg.Witness.LedgerEndpoints[did]; ok && ep != "" {
			ledgers[did] = ep
		} else {
			ledgers[did] = cfg.LedgerEndpoint
		}
	}
	witnesses := cfg.Witness.WitnessEndpoints
	if witnesses == nil {
		witnesses = map[string][]string{}
	}
	endpoints := &witness.StaticEndpoints{
		Ledgers:   ledgers,
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

// buildLogQueries constructs one HTTPLedgerQueryAPI per registered
// destination. The map is keyed by destination DID so judicial
// handlers can route per-destination read queries (case lookup,
// docket scan) to the right log.
func buildLogQueries(ledgerEndpoint string, registry *jurisdiction.Registry) (map[string]sdklog.LedgerQueryAPI, error) {
	out := make(map[string]sdklog.LedgerQueryAPI, registry.Len())
	for _, didStr := range registry.ExchangeDIDs() {
		q, err := sdklog.NewHTTPLedgerQueryAPI(sdklog.HTTPLedgerQueryAPIConfig{
			BaseURL: ledgerEndpoint,
			LogDID:  didStr,
		})
		if err != nil {
			return nil, fmt.Errorf("query api for %s: %w", didStr, err)
		}
		out[didStr] = q
	}
	return out, nil
}

func buildEntryFetcher(ledgerEndpoint string) types.EntryFetcher {
	return sdklog.NewHTTPEntryFetcher(sdklog.HTTPEntryFetcherConfig{
		BaseURL: ledgerEndpoint,
	})
}

func buildLeafReader(ledgerEndpoint string) smt.LeafReader {
	return smt.NewHTTPLeafReader(smt.HTTPLeafReaderConfig{
		BaseURL: ledgerEndpoint,
	})
}

// buildDIDResolver composes the FULL DID-resolution pipeline JN
// needs at runtime. Layered top-down:
//
//	CachingResolver (5-minute TTL)
//	    └── VendorDIDResolver (judicial-network vendor methods:
//	                           did:court:*, did:jnet:*, did:ccr:*)
//	          └── MethodRouter
//	                ├── "web" → WebDIDResolver  (HTTPS doc fetch)
//	                ├── "key" → KeyResolver     (multicodec-derived pubkey)
//	                └── "pkh" → PKHResolver     (CAIP-2 account address)
//
// # WHY ALL METHODS NEED A RESOLVER
//
// An earlier note here said did:pkh and did:key "are address/key
// based and need no Resolve() call." That was wrong for the
// v1.2.0 architecture: every JN verification path that calls
// resolver.Resolve(ctx, didStr) — including the SDK's
// attestation.VerifyEntryAttestationPolicy when a Constraint
// requires a DelegationResolver walk, and any audit / replay
// flow — needs the resolver to handle EVERY DID method the
// network might receive. Skipping did:key resolution means a
// did:key signer's pubkey extraction fails; skipping did:pkh
// means Ethereum-address signers cannot be looked up.
//
// # VENDOR-METHOD LAYER
//
// VendorDIDResolver translates JN-domain DID methods
// (did:court:tn:davidson → did:web:davidson.tn.court.gov,
//  did:jnet:tn:appellate → did:web:appellate.tn.jnet.gov,
//  did:ccr:agency:fbi-ncic → did:web:fbi-ncic.agency.ccr.org)
// to the SDK's canonical methods. Mappings live in
// judicial-network/did/mappings.go; the vendor resolver consults
// the inner MethodRouter for the translated DID.
//
// # CACHING
//
// Resolution is the verifier hot-path; an uncached
// WebDIDResolver issues a fresh HTTPS round-trip per lookup.
// 5-minute TTL is the SDK's CachingResolver default for production
// — short enough that key rotations propagate quickly, long enough
// to amortise repeated lookups of the same DID across many
// handlers within a single request batch.
func buildDIDResolver() (did.DIDResolver, error) {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

	web := did.NewWebDIDResolver(httpClient)
	key := did.NewKeyResolver()
	pkh, err := did.NewPKHResolverWithNamespaces(did.NamespaceEIP155)
	if err != nil {
		return nil, fmt.Errorf("buildDIDResolver: PKHResolver: %w", err)
	}

	router := did.NewMethodRouter()
	if err := router.Register("web", web); err != nil {
		return nil, fmt.Errorf("buildDIDResolver: register web: %w", err)
	}
	if err := router.Register("key", key); err != nil {
		return nil, fmt.Errorf("buildDIDResolver: register key: %w", err)
	}
	if err := router.Register("pkh", pkh); err != nil {
		return nil, fmt.Errorf("buildDIDResolver: register pkh: %w", err)
	}

	// Vendor layer translates judicial-network DID methods to
	// the SDK canonical methods registered above.
	vendor := did.NewVendorDIDResolver(router, judicialdid.AllMappings())

	return did.NewCachingResolver(vendor, 5*time.Minute), nil
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

func (schemaResolverShim) Resolve(_ context.Context, _ types.LogPosition, _ types.EntryFetcher) (*types.SchemaResolution, error) {
	return nil, fmt.Errorf("schema resolver not configured (boot-time shim — wire schemas-log resolver in production)")
}
