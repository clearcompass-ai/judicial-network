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
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
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

	"github.com/clearcompass-ai/attesta-tools/libs/crosslog"
	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
	"github.com/clearcompass-ai/judicial-network/cases/artifact"
	judicialdid "github.com/clearcompass-ai/judicial-network/did"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// buildJudicialDeps composes a judicial.Dependencies for the
// supplied registry + operational config. Returns an error only on
// unrecoverable misconfiguration (e.g., LedgerEndpoint set but
// invalid). Dev / test deployments may pass an empty
// LedgerEndpoint — the deps that need it remain nil and the
// dependent handlers return 500 with a clear error.
//
// ledgerHTTPClient is the boot-wired mTLS client built in main.go
// (BuildLedgerSubmitClient over cfg.Ledger{Cert,Key,CA}). When non-nil
// it is threaded into every SDK constructor that calls the ledger so
// peer-mTLS-required ledgers accept the connection. nil preserves the
// prior server-verify-only behaviour for dev / pre-cert deployments.
//
// SDK v1.25.0 wires the HTTP client through these config types:
//   - storage.HTTPContentStoreConfig.Client       (artifact store)
//   - sdklog.HTTPEntryFetcherConfig.Client
//   - sdklog.HTTPLedgerQueryAPIConfig.Client
//   - sdklog.HTTPCheckpointClientConfig.Client    (used by both
//     NewHTTPCheckpointClient and NewResolvingCheckpointClient)
//
// SDK GAP (tracked):
//   - witness.TreeHeadClient — config has HTTPTimeout but no Client
//     field; mTLS posture cannot be threaded yet.
//   - smt.HTTPProofReader / smt.HTTPLeafReader — same. The leaf-read
//     hot path (proof-anchored verifier) therefore cannot present a
//     client cert; a peer-mTLS-required ledger refuses these reads.
//     Fixed by a follow-up SDK PR adding Client *http.Client to those
//     config types.
func buildJudicialDeps(cfg config.Operational, registry *jurisdiction.Registry, ledgerHTTPClient *http.Client) (judicial.Dependencies, error) {
	witnessSets, err := buildWitnessSets(cfg)
	if err != nil {
		return judicial.Dependencies{}, fmt.Errorf("build witness sets: %w", err)
	}

	contentStore, err := newContentStore(cfg.ArtifactStoreEndpoint, ledgerHTTPClient)
	if err != nil {
		return judicial.Dependencies{}, fmt.Errorf("artifact content store: %w", err)
	}

	deps := judicial.Dependencies{
		Registry:     registry,
		Extractor:    schemas.NewRegistry(),
		ContentStore: contentStore,
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

	logQueries, err := buildLogQueries(cfg.LedgerEndpoint, registry, ledgerHTTPClient)
	if err != nil {
		return judicial.Dependencies{}, fmt.Errorf("build log queries: %w", err)
	}
	deps.LogQueries = logQueries
	deps.Fetcher = buildEntryFetcher(cfg.LedgerEndpoint, ledgerHTTPClient)
	deps.LeafReader = buildLeafReader(cfg, registry, witnessSets, ledgerHTTPClient)
	delegateQueriers, err := buildDelegateQueriers(cfg.LedgerEndpoint, registry, ledgerHTTPClient)
	if err != nil {
		return judicial.Dependencies{}, fmt.Errorf("build delegate queriers: %w", err)
	}
	deps.DelegateQueriers = delegateQueriers
	resolver, err := buildDIDResolver()
	if err != nil {
		return judicial.Dependencies{}, fmt.Errorf("build DID resolver: %w", err)
	}
	deps.Resolver = resolver
	deps.SchemaResolver = newSchemaResolverShim()
	deps.TreeHeadClient = buildTreeHeadClient(cfg, registry)
	deps.CheckpointClient = buildCheckpointClient(cfg, registry, ledgerHTTPClient)
	return deps, nil
}

// buildWitnessSets resolves cfg.Witness.Sets into the per-source-log
// *cosign.WitnessKeySet map that the cross-log verification paths read
// (crosslog.VerifyCrossLog).
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
	// libs/crosslog is domain-free: map the JN config rows into its neutral
	// WitnessSetSpec (identical fields) before building the keysets.
	specs := make([]crosslog.WitnessSetSpec, len(cfg.Witness.Sets))
	for i, s := range cfg.Witness.Sets {
		specs[i] = crosslog.WitnessSetSpec{LogDID: s.LogDID, WitnessDIDs: s.WitnessDIDs, QuorumK: s.QuorumK}
	}
	return crosslog.BuildWitnessSets(specs, networkID)
}

// loadBootstrapDoc reads + parses the network bootstrap document. It is the
// single shared trust input every component loads (ledger, witnesses, JN);
// the JN discovers its path from env (API_/LEDGER_NETWORK_BOOTSTRAP_FILE),
// so nothing about the deployment (native/docker/k8s) is in the Go — only
// the injected path differs.
func loadBootstrapDoc(path string) (*sdknetwork.BootstrapDocument, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc sdknetwork.BootstrapDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &doc, nil
}

// loadNetworkID derives the 32-byte cosign NetworkID from the bootstrap.
// Boot fails fast on any error — a misconfigured bootstrap means cross-
// component cosignature verification cannot succeed.
func loadNetworkID(path string) (cosign.NetworkID, error) {
	doc, err := loadBootstrapDoc(path)
	if err != nil {
		return cosign.NetworkID{}, err
	}
	ids, err := doc.IDs()
	if err != nil {
		return cosign.NetworkID{}, fmt.Errorf("derive network identity from %s: %w", path, err)
	}
	return ids.NetworkID, nil
}

// applyBootstrapDerivations fills env-/k8s-friendly defaults that come from
// the (env-pointed) bootstrap, so an operator turns the JN into an active
// auditor with toggles + K — never by hand-listing witness DIDs or peers in
// JSON. Same env surface works native / docker-compose / k8s.
//
//   - Witness.Sets: when empty and Witness.QuorumK > 0, derive ONE set for
//     the bootstrap's own log (exchange_did @ genesis_witness_set, K-of-N).
//   - GossipIngest.Peers: when ingest is on and no peers are listed, derive
//     one peer = the bootstrap log served by GossipIngest.PeerURL (the external
//     auditor's /v1/gossip), falling back to the ledger endpoint when unset.
//
// No-op when nothing needs deriving. When something does but the bootstrap
// path is empty, the downstream builder surfaces the precise error.
func applyBootstrapDerivations(ctx context.Context, cfg config.Operational) (config.Operational, error) {
	needWitness := len(cfg.Witness.Sets) == 0 && cfg.Witness.QuorumK > 0
	needPeer := cfg.GossipIngest.Enabled && len(cfg.GossipIngest.Peers) == 0
	if (!needWitness && !needPeer) || cfg.NetworkBootstrapFile == "" {
		return cfg, nil
	}
	doc, err := loadBootstrapDoc(cfg.NetworkBootstrapFile)
	if err != nil {
		return cfg, fmt.Errorf("bootstrap derivations: %w", err)
	}
	if doc.ExchangeDID == "" {
		return cfg, fmt.Errorf("bootstrap %s missing exchange_did", cfg.NetworkBootstrapFile)
	}
	// Cheap validation before any network call (so a misconfigured quorum fails
	// fast, not after discovery).
	if needWitness {
		if len(doc.GenesisWitnessSet) == 0 {
			return cfg, fmt.Errorf("bootstrap %s has no genesis_witness_set to derive a witness set from", cfg.NetworkBootstrapFile)
		}
		if cfg.Witness.QuorumK > len(doc.GenesisWitnessSet) {
			return cfg, fmt.Errorf("API_WITNESS_QUORUM_K=%d exceeds N=%d witnesses in bootstrap",
				cfg.Witness.QuorumK, len(doc.GenesisWitnessSet))
		}
	}
	// Key both the witness set and the peer on the source log's GOSSIP-ORIGINATOR
	// did:key (what STHs are originated under), discovered from the ledger's
	// /v1/log-info — NOT exchange_did. gossipverify routes WitnessSets[ev.Originator],
	// so keying by exchange_did leaves every STH unmatched.
	// nil ledgerHTTPClient: bootstrap derivation runs in loadConfig BEFORE the
	// mTLS client is materialised, so the discovery probe uses a plain
	// client. A peer-mTLS-required ledger will refuse the probe — in that
	// posture, operators must hand-list witness sets / peers (set
	// API_GOSSIP_INGEST_DISCOVER_ORIGINATOR=false) so derivation is skipped.
	logDID, err := gossipOriginatorLogDID(ctx, cfg, doc, nil)
	if err != nil {
		return cfg, fmt.Errorf("bootstrap derivations: %w", err)
	}
	if needWitness {
		cfg.Witness.Sets = []config.WitnessSetConfig{{
			LogDID:      logDID,
			WitnessDIDs: append([]string(nil), doc.GenesisWitnessSet...),
			QuorumK:     cfg.Witness.QuorumK,
		}}
	}
	if needPeer {
		// The verify-only ingest pulls the external auditor's curated feed (its
		// detection findings + relayed gossip), not the ledger's raw feed. Fall
		// back to the ledger endpoint when no auditor URL is configured.
		base := cfg.LedgerEndpoint
		if cfg.GossipIngest.PeerURL != "" {
			base = cfg.GossipIngest.PeerURL
		}
		cfg.GossipIngest.Peers = []config.GossipPeerConfig{{
			LogDID:  logDID,
			BaseURL: base,
		}}
	}
	return cfg, nil
}

// gossipOriginatorLogDID returns the DID the gossip witness set + peer must key
// on: the source log's operational gossip-originator did:key when
// DiscoverOriginator is set (resolved from the ledger's /v1/log-info ledger_did),
// else the bootstrap exchange_did. Self-report is safe for ROUTING — the trust
// root is the K-of-N witness cosignatures, which a peer cannot forge by
// misreporting its DID.
func gossipOriginatorLogDID(ctx context.Context, cfg config.Operational, doc *sdknetwork.BootstrapDocument, ledgerHTTPClient *http.Client) (string, error) {
	if !cfg.GossipIngest.DiscoverOriginator {
		return doc.ExchangeDID, nil
	}
	if cfg.LedgerEndpoint == "" {
		return "", fmt.Errorf("originator discovery enabled but LedgerEndpoint empty (set API_LEDGER_ENDPOINT or disable API_GOSSIP_INGEST_DISCOVER_ORIGINATOR)")
	}
	info, err := discoverLedgerOriginator(ctx, cfg.LedgerEndpoint, ledgerHTTPClient)
	if err != nil {
		return "", fmt.Errorf("discover gossip originator from %s/v1/log-info: %w", cfg.LedgerEndpoint, err)
	}
	if info.LedgerDID == "" {
		return "", fmt.Errorf("ledger %s advertised empty ledger_did", cfg.LedgerEndpoint)
	}
	// Cross-network guard: refuse to bind trust to a log on a different network
	// (only when both sides advertise a comparable id).
	if ids, derr := doc.IDs(); derr == nil {
		if want := networkIDHexPrefix(ids.NetworkID); want != "" && info.NetworkID != "" && info.NetworkID != want {
			return "", fmt.Errorf("ledger %s network_id %q != bootstrap %q — refusing to bind trust across networks",
				cfg.LedgerEndpoint, info.NetworkID, want)
		}
	}
	if info.LogDID != "" && doc.ExchangeDID != "" && info.LogDID != doc.ExchangeDID {
		slog.Warn("jn: ledger log_did != bootstrap exchange_did",
			"ledger", cfg.LedgerEndpoint, "advertised", info.LogDID, "bootstrap", doc.ExchangeDID)
	}
	slog.Info("jn: bound gossip witness set to discovered originator",
		"canonical_did", doc.ExchangeDID, "originator_did", info.LedgerDID)
	return info.LedgerDID, nil
}

// ledgerLogInfo is the subset of the ledger's GET /v1/log-info the JN needs to
// bind trust: the operational gossip-originator did:key (ledger_did), the
// canonical log DID, and the network_id prefix (for the cross-network guard).
type ledgerLogInfo struct {
	LogDID    string `json:"log_did"`
	LedgerDID string `json:"ledger_did"`
	NetworkID string `json:"network_id"`
}

// discoverLedgerOriginator fetches GET {ledgerEndpoint}/v1/log-info, retrying
// with bounded exponential backoff (the ledger may still be starting). Returns
// once it answers, or ctx is cancelled / retries are spent.
//
// ledgerHTTPClient is the boot-wired mTLS client; nil falls back to a
// plain &http.Client{Timeout} so dev/test against a plaintext ledger keeps
// working (same posture as the pre-mTLS version of this function).
func discoverLedgerOriginator(ctx context.Context, ledgerEndpoint string, ledgerHTTPClient *http.Client) (ledgerLogInfo, error) {
	url := strings.TrimRight(ledgerEndpoint, "/") + "/v1/log-info"
	hc := ledgerHTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	const maxAttempts = 6
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return ledgerLogInfo{}, ctx.Err()
		}
		info, err := fetchLedgerLogInfo(ctx, url, hc)
		if err == nil {
			return info, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ledgerLogInfo{}, ctx.Err()
		case <-time.After(retryBackoff(attempt)):
		}
	}
	return ledgerLogInfo{}, lastErr
}

func fetchLedgerLogInfo(ctx context.Context, url string, hc *http.Client) (ledgerLogInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ledgerLogInfo{}, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return ledgerLogInfo{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ledgerLogInfo{}, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	var info ledgerLogInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&info); err != nil {
		return ledgerLogInfo{}, fmt.Errorf("decode %s: %w", url, err)
	}
	return info, nil
}

// retryBackoff is exponential (1s,2s,4s,…) capped at 16s.
func retryBackoff(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt-1)) * time.Second
	if d > 16*time.Second {
		return 16 * time.Second
	}
	return d
}

// networkIDHexPrefix renders the first-8-bytes hex of the NetworkID, matching
// the ledger's /v1/log-info "network_id" format (cmd/ledger networkIDHex).
func networkIDHexPrefix(nid cosign.NetworkID) string {
	if nid == (cosign.NetworkID{}) {
		return ""
	}
	return fmt.Sprintf("%x", nid[:8])
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
	ledgers := ledgerEndpointMap(cfg, registry)
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

// buildCheckpointClient constructs the DID-addressed horizon client used by
// anchor publishing (it must embed the durable /v1/tree/horizon, not the live
// head). It resolves log DID → ledger URL through the SAME static endpoint map
// as buildTreeHeadClient (witness.StaticEndpoints satisfies sdklog.EndpointResolver);
// no witness fallback applies — witnesses don't serve the horizon. Returns nil in
// dev/test mode (empty LedgerEndpoint) → the publish-anchor handler surfaces 503.
func buildCheckpointClient(cfg config.Operational, registry *jurisdiction.Registry, ledgerHTTPClient *http.Client) *sdklog.ResolvingCheckpointClient {
	if cfg.LedgerEndpoint == "" {
		return nil
	}
	endpoints := &witness.StaticEndpoints{Ledgers: ledgerEndpointMap(cfg, registry)}
	ccfg := sdklog.HTTPCheckpointClientConfig{
		Client: ledgerHTTPClient, // nil ⇒ plain http.Client w/ Timeout
	}
	if cfg.Witness.HTTPTimeout > 0 {
		ccfg.Timeout = cfg.Witness.HTTPTimeout
	}
	return sdklog.NewResolvingCheckpointClient(endpoints, ccfg)
}

// ledgerEndpointMap maps every log the binary must reach a tree head for →
// its ledger base URL. Two sources:
//   - registered JN court destinations (registry.ExchangeDIDs())
//   - the audited logs from cfg.Witness.Sets — which need NOT be JN
//     destinations (e.g. the ledger's own log DID from the bootstrap)
//
// Per-log overrides (cfg.Witness.LedgerEndpoints) win; otherwise the default
// LedgerEndpoint. Without the witness-set logs here, the equivocation scanner
// fails to resolve them ("no ledger endpoint for <source log>").
func ledgerEndpointMap(cfg config.Operational, registry *jurisdiction.Registry) map[string]string {
	ledgers := map[string]string{}
	put := func(did string) {
		if did == "" {
			return
		}
		if _, ok := ledgers[did]; ok {
			return
		}
		if ep, ok := cfg.Witness.LedgerEndpoints[did]; ok && ep != "" {
			ledgers[did] = ep
		} else {
			ledgers[did] = cfg.LedgerEndpoint
		}
	}
	for _, did := range registry.ExchangeDIDs() {
		put(did)
	}
	for _, set := range cfg.Witness.Sets {
		put(set.LogDID)
	}
	return ledgers
}

// buildLogQueries constructs one HTTPLedgerQueryAPI per registered
// destination. The map is keyed by destination DID so judicial
// handlers can route per-destination read queries (case lookup,
// docket scan) to the right log. ledgerHTTPClient (nil ⇒ SDK default)
// presents the JN's client cert when peer mTLS is configured.
func buildLogQueries(ledgerEndpoint string, registry *jurisdiction.Registry, ledgerHTTPClient *http.Client) (map[string]sdklog.LedgerQueryAPI, error) {
	out := make(map[string]sdklog.LedgerQueryAPI, registry.Len())
	for _, didStr := range registry.ExchangeDIDs() {
		q, err := sdklog.NewHTTPLedgerQueryAPI(sdklog.HTTPLedgerQueryAPIConfig{
			BaseURL: ledgerEndpoint,
			LogDID:  didStr,
			Client:  ledgerHTTPClient, // nil ⇒ SDK default (server-verify only)
		})
		if err != nil {
			return nil, fmt.Errorf("query api for %s: %w", didStr, err)
		}
		out[didStr] = q
	}
	return out, nil
}

func buildEntryFetcher(ledgerEndpoint string, ledgerHTTPClient *http.Client) types.EntryFetcher {
	return sdklog.NewHTTPEntryFetcher(sdklog.HTTPEntryFetcherConfig{
		BaseURL: ledgerEndpoint,
		Client:  ledgerHTTPClient, // nil ⇒ SDK default (server-verify only)
	})
}

// buildDelegateQueriers constructs one verification.LedgerDelegateQuerier per
// registered destination — the read-time shim Stage 6's delegation walker
// consumes (via DelegateDIDQuerier interface). The map is keyed by destination
// DID so each query routes to the right log. ledgerHTTPClient (nil ⇒ plain
// http.Client with timeout) carries the JN's client cert when peer mTLS is
// configured.
//
// The SDK's LedgerQueryAPI does not yet expose QueryByDelegateDID; this shim
// fills that gap until the SDK lands the typed query method (then this folds
// into buildLogQueries and the shim is deleted).
func buildDelegateQueriers(ledgerEndpoint string, registry *jurisdiction.Registry, ledgerHTTPClient *http.Client) (map[string]verification.DelegateDIDQuerier, error) {
	out := make(map[string]verification.DelegateDIDQuerier, registry.Len())
	for _, didStr := range registry.ExchangeDIDs() {
		q, err := verification.NewLedgerDelegateQuerier(verification.LedgerDelegateQuerierConfig{
			BaseURL: ledgerEndpoint,
			LogDID:  didStr,
			Client:  ledgerHTTPClient, // nil ⇒ default plain client w/ Timeout
		})
		if err != nil {
			return nil, fmt.Errorf("delegate querier for %s: %w", didStr, err)
		}
		out[didStr] = q
	}
	return out, nil
}

// buildLeafReader returns the smt.LeafReader the SDK verifier walkers
// (EvaluateAuthority / EvaluateOrigin / WalkDelegationTree) read SMT state
// through. When the own log's witness set is known it returns a
// PROOF-ANCHORED reader (verification.VerifyingLeafReader): every read is
// verified against the K-of-N witness-cosigned horizon, so a judicial
// ruling on ledger state trusts the witness quorum, not the ledger. When
// no witness set resolves to the ledger endpoint (dev / test, or a
// witness-less deployment) it falls back to the plain HTTPLeafReader —
// reads work but are UNVERIFIED — and logs that loudly so a deployer
// knows the trust boundary is the ledger itself.
func buildLeafReader(cfg config.Operational, registry *jurisdiction.Registry, witnessSets map[string]*cosign.WitnessKeySet, ledgerHTTPClient *http.Client) smt.LeafReader {
	plain := smt.NewHTTPLeafReader(smt.HTTPLeafReaderConfig{BaseURL: cfg.LedgerEndpoint})

	set, logDID := primaryWitnessSet(cfg, registry, witnessSets)
	if set == nil {
		slog.Warn("jn: leaf reader is UNVERIFIED — no witness set resolves to the ledger endpoint; "+
			"SMT-state decisions trust the ledger. Configure API_WITNESS_QUORUM_K (env-derived) or "+
			"witness.sets to enable proof-anchored reads",
			"ledger", cfg.LedgerEndpoint)
		return plain
	}

	// The checkpoint client (horizon), proof reader, and the leaf endpoint
	// all target the SAME ledger URL — the leaf, its proof, and the horizon
	// the proof is verified against must come from the one log being read.
	//
	// SDK GAP (tracked): smt.HTTPProofReaderConfig + smt.HTTPLeafReaderConfig
	// do not yet expose Client *http.Client; the proof/leaf hot path
	// therefore cannot present a client cert. Peer-mTLS-required ledgers
	// will refuse these reads until a follow-up SDK PR adds the field.
	cp := sdklog.NewHTTPCheckpointClient(sdklog.HTTPCheckpointClientConfig{
		BaseURL: cfg.LedgerEndpoint,
		Timeout: cfg.Witness.HTTPTimeout, // zero → SDK default
		Client:  ledgerHTTPClient,        // nil ⇒ plain client (SDK default)
	})
	pr := smt.NewHTTPProofReader(smt.HTTPProofReaderConfig{
		BaseURL: cfg.LedgerEndpoint,
		Timeout: cfg.Witness.HTTPTimeout, // zero → SDK default
	})
	vr, err := verification.NewVerifyingLeafReader(verification.VerifyingLeafReaderConfig{
		Checkpoint: cp,
		Proofs:     pr,
		WitnessSet: set,
		HorizonTTL: cfg.Witness.CacheTTL, // zero → default
	})
	if err != nil {
		// set is non-nil here, so the constructor cannot fail on a nil dep;
		// fall back defensively rather than panic the binary.
		slog.Warn("jn: verifying leaf reader construction failed; falling back to UNVERIFIED reader",
			"error", err, "ledger", cfg.LedgerEndpoint)
		return plain
	}
	slog.Info("jn: leaf reads are proof-anchored on the witness-cosigned horizon",
		"ledger", cfg.LedgerEndpoint, "log_did", logDID, "quorum", set.Quorum())
	return vr
}

// primaryWitnessSet returns the witness set for the log served at
// cfg.LedgerEndpoint — the trust root for proof-anchored leaf reads.
//
// The leaf reader reads leaves + proofs + horizon from cfg.LedgerEndpoint,
// which serves exactly one log. That log's witness set is found by reverse-
// mapping the ledger-endpoint table: among log DIDs that (a) have a
// configured witness set and (b) resolve to cfg.LedgerEndpoint, the own log
// is the unique match. Picking the wrong set fails loudly (cosignatures
// won't verify → every read errors), so this returns (nil, "") when none
// or several match — dev / test with no sets, or an ambiguous multi-log
// config — and the caller falls back to an unverified reader rather than
// guessing a trust root.
func primaryWitnessSet(cfg config.Operational, registry *jurisdiction.Registry, witnessSets map[string]*cosign.WitnessKeySet) (*cosign.WitnessKeySet, string) {
	endpoints := ledgerEndpointMap(cfg, registry)
	var found *cosign.WitnessKeySet
	var foundDID string
	for did, set := range witnessSets {
		if set == nil || endpoints[did] != cfg.LedgerEndpoint {
			continue
		}
		if found != nil {
			return nil, "" // ambiguous — refuse to guess the trust root
		}
		found = set
		foundDID = did
	}
	return found, foundDID
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
//
//	did:jnet:tn:appellate → did:web:appellate.tn.jnet.gov,
//	did:ccr:agency:fbi-ncic → did:web:fbi-ncic.agency.ccr.org)
//
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
//
// httpClient (nil ⇒ a plain &http.Client{Timeout: 30s}) carries the
// JN's client cert when the artifact store is fronted by mTLS — same
// instance the ledger-bound surfaces use, since today the JN does not
// distinguish artifact-store cert material from ledger cert material.
// (If/when those diverge, take a second *http.Client parameter and
// hand it in here.)
//
// SDK v1.25.0: HTTPContentStoreConfig.Timeout is gone; the new
// required field is Client *http.Client. NewHTTPContentStore now
// returns (*HTTPContentStore, error). The in-memory branch keeps its
// nil-error shape so callers see a uniform return signature.
func newContentStore(endpoint string, httpClient *http.Client) (storage.ContentStore, error) {
	if endpoint == "" {
		return storage.NewInMemoryContentStore(), nil
	}
	c := httpClient
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	return storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{
		BaseURL: endpoint,
		Client:  c,
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
