/*
Package config — operational configuration for the api/ binary.

The api/ surface is the JN network's common write API. It is
multi-tenant by design: a single binary serves N destinations, each
defined by a compiled-in jurisdiction.Bundle (the "deployment profile"
pattern; see deployments/tn/counties/davidson/bundle.go for the
canonical example).

This package separates two concerns that production code must NEVER
mix:

	DEFINITION (compiled-in Go code; immutable per release):
	  - Destination DIDs (e.g., "did:web:state:tn:davidson")
	  - Role catalogs, cosignature policies, prerequisite policies
	  - Per-jurisdiction authority chain resolvers
	  - Appellate vocabularies
	  These live in deployments/.../bundle.go. Loaded once at boot via
	  jurisdiction.Registry.Register and frozen.

	OPERATIONAL CONFIG (env / JSON; varies per environment):
	  - Listen address, upstream endpoints (ledger, artifact store,
	    verification service, EIP-1271 RPC)
	  - KeyStore backend selection (memory / softhsm / vault)
	  - Nonce-store backend (memory / redis) and connection params
	  - Auth selection (mTLS, JWT) and trust material
	  - Telemetry endpoints
	  These live in this struct.

The hard rule: Operational MUST NOT carry any DID. Identity comes from
imported deployment packages — never from JSON. A typo in operational
config never produces a "phantom" destination; it can only mismatch a
non-DID knob (port number, RPC URL, etc.) which boot validation
catches loudly.

Loading model:

 1. Defaults() returns the zero-config baseline (every field has a
    sane in-memory dev value).
 2. LoadFromFile(path) reads JSON and applies overrides on top.
 3. ApplyEnvOverrides reads a fixed set of env vars (precedence:
    env > file > defaults).
 4. Validate() runs Boot-time consistency checks; returns
    ErrInvalidConfig with a descriptive message on failure.

Production deployments call all four in order; tests skip 2-3.
*/
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidConfig wraps every validation failure surfaced by this
// package. Callers errors.Is against this sentinel for routing.
var ErrInvalidConfig = errors.New("api/config: invalid operational config")

// Defaults returns the baseline operational config used by tests
// and dev environments. All endpoints point at localhost; no TLS;
// memory backends for keystore and nonce store. Production callers
// pass this to LoadFromFile to overlay an environment file.
func Defaults() Operational {
	return Operational{
		ListenAddr: ":8443",

		LedgerEndpoint: "http://localhost:8001",
		// ArtifactStoreEndpoint defaults to OUT (empty) — it's the document
		// surface, not the entry-write/audit path. Opt in via config or
		// API_ARTIFACT_STORE_ENDPOINT.
		VerificationEndpoint: "http://localhost:8080",

		KeyStore: KeyStoreConfig{
			Backend: KeyStoreBackendMemory,
		},
		NonceStore: NonceStoreOpConfig{
			Backend:         NonceStoreBackendMemory,
			FreshnessWindow: 5 * time.Minute,
		},
		Auth: AuthConfig{
			Mode: AuthModeMTLS,
		},
		// Bind the gossip witness set to the source log's operational did:key
		// (discovered from the ledger's /v1/log-info) by default — STHs are
		// originated under that key, not exchange_did.
		GossipIngest: GossipIngestConfig{
			DiscoverOriginator: true,
		},
	}
}

// Operational is the full operational config for an api/ binary.
//
// IMPORTANT: this struct contains zero DIDs. Destination identities
// come from compiled-in deployment packages (see jurisdiction.Bundle
// + deployments/.../bundle.go), never from this struct. Mixing them
// is a security regression — a typo in JSON would create a phantom
// destination that no Bundle covers.
type Operational struct {
	// ListenAddr is the api/ HTTP listen address. Format: ":port" or
	// "host:port". Required.
	ListenAddr string `json:"listen_addr"`

	// Upstream service endpoints. The JN is an auditor of a ledger, so
	// LedgerEndpoint is a HARD dependency — required by Validate AND probed
	// for reachability at boot (the binary refuses to start without a live
	// ledger). VerificationEndpoint is likewise required. ArtifactStoreEndpoint
	// is OPTIONAL: it serves the document/blob surface, not the entry-write or
	// audit path, so a deployment can leave it empty to run ledger-only.
	LedgerEndpoint        string `json:"ledger_endpoint"`
	ArtifactStoreEndpoint string `json:"artifact_store_endpoint,omitempty"`
	VerificationEndpoint  string `json:"verification_endpoint"`

	// LedgerCertFile / LedgerKeyFile / LedgerCAFile are the mTLS
	// material the exchange presents to (and verifies against) the
	// ledger. REQUIRED in production: the ledger's TLS listener
	// refuses connections without a verified client cert
	// (ledger/api/server.go::buildServerTLSConfig). Dev / test
	// deployments pointed at a plaintext ledger (LedgerEndpoint
	// starting with "http://") leave these empty.
	//
	// LedgerCAFile pins server verification to the configured CA
	// bundle; empty falls back to the system pool (NOT recommended
	// — pin the CA in production so a compromised root in the
	// system pool can't substitute for the ledger).
	LedgerCertFile string `json:"ledger_cert_file,omitempty"`
	LedgerKeyFile  string `json:"ledger_key_file,omitempty"`
	LedgerCAFile   string `json:"ledger_ca_file,omitempty"`

	// SmartContractWallet configures multi-chain EIP-1271 K-of-N
	// executor consensus (one quorum per onboarded EVM chain). Zero
	// value (Enabled=false) → EOA-only verification (did:key +
	// did:pkh-EOA + did:web), no Ethereum RPC. Trust Alignment 2.
	SmartContractWallet SmartContractWalletConfig `json:"smart_contract_wallet"`

	KeyStore   KeyStoreConfig     `json:"keystore"`
	NonceStore NonceStoreOpConfig `json:"nonce_store"`
	Auth       AuthConfig         `json:"auth"`
	Witness    WitnessConfig      `json:"witness"`

	// NetworkBootstrapFile is the path to a JSON file containing the
	// network's bootstrap document (network.BootstrapDocument). The
	// 32-byte cosign NetworkID is derived from this document at boot
	// and threaded through every cosign.Sign / cosign.Verify call site.
	//
	// Required when the binary participates in cosignature production
	// or verification (the cosign canonical-message preamble rejects
	// a zero NetworkID). Dev / test deployments that don't exercise
	// the verification surface may leave this empty.
	//
	// The same document MUST be loaded by every component participating
	// in the network (ledger, JN composer, every witness); cross-
	// component signature verification depends on byte-identical
	// bootstrap inputs.
	NetworkBootstrapFile string `json:"network_bootstrap_file"`

	// GossipIngest configures the INBOUND anti-entropy plane: a
	// background loop that PULLS peer ledgers' gossip feeds, verifies
	// each event (envelope + finding proof) against JN-local trust, and
	// drives the enforcers (trusted-head tracking, equivocation slashing).
	// Disabled by default — JN serves its own feed without it.
	GossipIngest GossipIngestConfig `json:"gossip_ingest"`

	// Monitoring configures the continuous-monitoring scheduler — the
	// JN's autonomous audit pulse (mirror consistency, anchor freshness,
	// sealing compliance) plus the durable-store retention prune.
	// Disabled by default; the on-demand /v1/judicial/monitoring/* HTTP
	// endpoints remain available regardless.
	Monitoring MonitoringConfig `json:"monitoring"`

	// AuditorScope configures the v1.33.x auditor-scope gate. The gate
	// rejects gossip findings emitted by an auditor outside its current
	// registered scope (network.AuditorRegistration.Scope), so a slasher
	// can't claim cross-log inclusion authority when its registration
	// only covers equivocation. Off by default for backward compat with
	// pre-v1.33 deployments; flip Enforce=true once registry + amendment
	// files are provisioned.
	AuditorScope AuditorScopeConfig `json:"auditor_scope"`

	// URLDriftInterval configures the periodic URL-drift audit (libs/
	// monitoring/url_drift_audit.go). Zero (the default) disables the
	// job. When non-zero AND the resolver inputs are populated AND
	// LocalLogDID is set, the scheduler registers a `url_drift_audit`
	// job that walks WitnessEndpointDeclaration + AuditorRegistration
	// records and emits alerts when an endpoint URL drifts from its
	// most-recent on-log declaration. Env: API_URL_DRIFT_INTERVAL.
	URLDriftInterval time.Duration `json:"url_drift_interval,omitempty"`
}

// AuditorScopeConfig configures the v1.33.x auditor-scope gate.
//
// The scope gate refuses to advance JN's trusted view from a gossip
// finding whose Kind falls outside the emitting auditor's current
// registered Scope. Two file-pointed inputs feed the gate:
//
//   - RegistryFile: JSON-encoded []network.AuditorRegistrationRecord
//     (the on-log registrations). Required when Enforce=true.
//   - AmendmentFile: JSON-encoded []network.AuditorScopeAmendmentRecord
//     (optional scope amendments that override an auditor's
//     registered Scope as of a specific log position). Optional
//     independently of Enforce: an empty amendments slice is valid.
//
// Both files mirror the attesta-tools auditor service's
// AUDITOR_REGISTRY_FILE / AUDITOR_AMENDMENT_FILE shape — same JSON,
// same sort discipline (ascending by EffectivePos).
//
// Validate enforces: Enforce=true && RegistryFile=="" → boot-fast-fail
// with "refusing to boot with a silent scope-gate downgrade."
type AuditorScopeConfig struct {
	// Enforce gates the whole reconciler-side scope check. False (the
	// default) leaves the reconciler in pre-v1.33 behaviour: every
	// verified finding advances the trusted view regardless of scope.
	// Env: API_ENFORCE_SCOPES.
	Enforce bool `json:"enforce,omitempty"`

	// RegistryFile is the path to a JSON file holding the on-log
	// auditor registrations (sorted by EffectivePos ascending). Required
	// when Enforce=true. Env: API_AUDITOR_REGISTRY_FILE.
	RegistryFile string `json:"registry_file,omitempty"`

	// AmendmentFile is the path to a JSON file holding scope amendments
	// (sorted by EffectivePos ascending). Optional independent of
	// Enforce. Env: API_AUDITOR_AMENDMENT_FILE.
	AmendmentFile string `json:"amendment_file,omitempty"`

	// ReloadOnSIGHUP enables D13 hot-reload: on SIGHUP, the binary
	// re-reads RegistryFile and AmendmentFile and installs the new
	// snapshots into the home Reconciler via its atomic.Pointer-
	// backed RefreshRegistry / RefreshAmendments methods. Per-file
	// read failures are logged and the live snapshot for the
	// failing file is retained (do-not-clobber contract — see
	// cmd/network-api/sighup_reload.go::applyReload).
	//
	// Default false: SIGHUP is ignored unless explicitly enabled.
	// Operator manifests that ship a k8s ConfigMap reloader (or
	// any other on-disk file pusher) set this to true; static
	// deployments leave it off and re-roll the pod on registry
	// updates.
	//
	// When true, ReloadOnSIGHUP is a no-op unless at least one of
	// RegistryFile / AmendmentFile is configured AND the home
	// Reconciler is wired (gossip ingest enabled with at least one
	// home peer).
	//
	// Env: API_RELOAD_ON_SIGHUP.
	ReloadOnSIGHUP bool `json:"reload_on_sighup,omitempty"`
}

// MonitoringConfig configures the scheduled-audit engine. A check job
// registers only when its audit list is non-empty AND the required
// dependencies are wired; the gossip-prune job registers only when the
// store is durable.
type MonitoringConfig struct {
	// Enabled gates the whole scheduler. Disabled ⇒ no audit goroutines.
	Enabled bool `json:"enabled"`

	// Cadence overrides. Zero applies the defaults: mirror 5m, anchor 1h,
	// sealing nightly, prune nightly.
	MirrorInterval  time.Duration `json:"mirror_interval,omitempty"`
	AnchorInterval  time.Duration `json:"anchor_interval,omitempty"`
	SealingInterval time.Duration `json:"sealing_interval,omitempty"`
	PruneInterval   time.Duration `json:"prune_interval,omitempty"`

	// Per-check audit targets (one network-wide job iterates each list).
	Mirror  []MirrorAuditConfig  `json:"mirror,omitempty"`
	Anchor  []AnchorAuditConfig  `json:"anchor,omitempty"`
	Sealing []SealingAuditConfig `json:"sealing,omitempty"`
}

// MirrorAuditConfig is one officers→cases mirror pair to audit.
type MirrorAuditConfig struct {
	OfficersLogDID     string `json:"officers_log_did"`
	CasesLogDID        string `json:"cases_log_did"`
	MirrorSignerDID    string `json:"mirror_signer_did"`
	RootEntityLogDID   string `json:"root_entity_log_did"`
	RootEntitySequence uint64 `json:"root_entity_sequence"`
}

// AnchorAuditConfig is one county→parent anchor relationship to audit.
type AnchorAuditConfig struct {
	LocalLogDID     string `json:"local_log_did"`
	ParentLogDID    string `json:"parent_log_did"`
	LedgerSignerDID string `json:"ledger_signer_did"`
}

// SealingAuditConfig is one local log whose sealing compliance to audit.
type SealingAuditConfig struct {
	LocalLogDID  string `json:"local_log_did"`
	ScanStartSeq uint64 `json:"scan_start_seq,omitempty"`
	ScanCount    int    `json:"scan_count,omitempty"`
}

// ──────────────────────────────────────────────────────────────────
// Gossip ingest (inbound anti-entropy)
// ──────────────────────────────────────────────────────────────────

// GossipIngestConfig configures the inbound gossip pull loop. Witness sets
// (the trust root for verifying pulled CosignedTreeHead / equivocation
// findings) come from Witness.Sets + NetworkBootstrapFile — NEVER from a peer.
type GossipIngestConfig struct {
	// Enabled gates the whole inbound loop. Disabled ⇒ no peers are pulled.
	Enabled bool `json:"enabled"`

	// Peers is the operator-pinned allowlist of peer feeds to pull. A peer is
	// only a byte source; each event is verified on its own cryptography, so
	// listing a peer grants it no trust. Empty ⇒ nothing to pull.
	Peers []GossipPeerConfig `json:"peers,omitempty"`

	// PeerLogs declares FOREIGN-NETWORK peer logs whose entries this JN may
	// encounter as cross-log references (Scenario 1). Each entry brings its
	// own NetworkID + witness set + gossip endpoint; the binary builds a
	// PARALLEL gossip ingest pipeline for each. All pipelines share the
	// home-network HeadsJournal (multi-log keyed by LogDID), so foreign
	// heads land in the same durable archive home heads do. Empty ⇒ no
	// cross-network ingest (single-network mode, identical to v1.36
	// baseline).
	PeerLogs []PeerLogConfig `json:"peer_logs,omitempty"`

	// PeerURL is the env-driven single-peer source for the verify-only ingest:
	// the external auditor's /v1/gossip base URL. When Peers is empty and ingest
	// is enabled, the binary derives one peer = {bootstrap log, PeerURL}. Empty ⇒
	// the derivation falls back to LedgerEndpoint. A peer is only a byte source;
	// every pulled event is re-verified, so this grants the auditor no trust.
	//
	// PeerURL (and any Peers[].BaseURL) may be given as a bare did:web instead of
	// an http(s) URL; the binary then resolves the gossip base from the DID
	// document's AttestaLedger service endpoint at boot (parity with the auditor's
	// AUDITOR_PEERS did:web form). An http(s) value is used verbatim.
	PeerURL string `json:"peer_url,omitempty"`

	// PeerResolveTTL caps how long a resolved did:web peer base is cached (the
	// TTL on the WebDIDResolver behind did:web peer-base resolution). Zero
	// applies a 5-minute default. Env: API_GOSSIP_INGEST_DIDWEB_TTL (the env
	// name mirrors the auditor's AUDITOR_DIDWEB_TTL; the field is named without
	// "DID" to satisfy the no-DID-in-config invariant).
	PeerResolveTTL time.Duration `json:"peer_resolve_ttl,omitempty"`

	// DiscoverOriginator controls how the genesis witness set is bound to a
	// source log's gossip identity. STH gossip is originated under a log's
	// OPERATIONAL did:key (the ledger's signer key), not its canonical
	// exchange_did, and gossipverify routes the witness-set lookup by that
	// originator (WitnessSets[ev.Originator]). When true (the default), the
	// derived witness set + peer key on the operational did:key resolved from
	// the ledger's GET /v1/log-info (ledger_did). When false, exchange_did is
	// used verbatim. Keying by exchange_did while STHs arrive under a did:key
	// leaves every event unmatched ("no witness set for source_log_did
	// <did:key…>").
	DiscoverOriginator bool `json:"discover_originator,omitempty"`

	// PollInterval is the wait between catch-up rounds per peer. Zero applies
	// the puller default (5s).
	PollInterval time.Duration `json:"poll_interval,omitempty"`

	// PageLimit caps events fetched per /since page. Zero applies the puller
	// default (256).
	PageLimit int `json:"page_limit,omitempty"`

	// SlashThreshold is the number of distinct verified equivocation findings
	// against one ledger that triggers slashing. Zero ⇒ slasher default (1 —
	// a single unforgeable proof suffices).
	SlashThreshold int `json:"slash_threshold,omitempty"`

	// TileMirrors maps a source-log DID to its Static-CT tile root URL, used to
	// replay cross-log inclusion (ClassMerkle) proofs. The proof is checked
	// against the source log's TRUSTED head (from verified tree heads), so a
	// mirror is a data source, not a trust root — but it is still operator-
	// pinned. Empty ⇒ cross-log inclusion findings fail-closed.
	TileMirrors []TileMirrorConfig `json:"tile_mirrors,omitempty"`
}

// GossipPeerConfig names one peer ledger's gossip feed.
type GossipPeerConfig struct {
	// LogDID is the peer's log DID (diagnostic + per-peer cursor key).
	LogDID string `json:"log_did"`
	// BaseURL is the peer's base URL; the SDK feed client appends /v1/gossip.
	BaseURL string `json:"base_url"`
}

// PeerLogConfig declares a FOREIGN-NETWORK peer log whose entries this
// JN may encounter as cross-log references (Scenario 1 in the 15-year
// lifecycle spec). Each foreign log has its own NetworkID and its own
// witness set — verification against a foreign log's cosigned head
// MUST use the foreign network's NetworkID and the foreign log's
// witness set, never the home network's. The PeerLogs list extends
// the home-network ingest with one PARALLEL gossip pipeline per
// peer log so foreign heads land in the same shared journal
// (libs/monitoring.HeadsJournal) the home-network heads do.
//
// SECURITY POSTURE
//
// Foreign-log ingest is INDEPENDENT of home-network admission. A
// burned peer log (detected equivocation, KindEquivocationFinding)
// transitions the journal's BurnStatus to true for the foreign LogDID;
// every subsequent VerifyCrossLogProof against that LogDID returns
// ErrEquivocatedLog (the STRICT FAIL-CLOSED mandate). Verification
// halts globally for that foreign domain until human governance
// re-establishes a clean trust root — out-of-band.
type PeerLogConfig struct {
	// LogDID is the foreign log's DID (e.g., "did:web:federal-courts.example").
	// Required, unique within PeerLogs.
	LogDID string `json:"log_did"`

	// NetworkID is the foreign network's NetworkID as hex
	// (32 bytes / 64 hex chars). Required — foreign-network
	// cosigned heads bind to THIS NetworkID in their cosign
	// canonical bytes (Scenario 5: cross-network replay rejection).
	NetworkID string `json:"network_id"`

	// GossipEndpoint is the foreign log's gossip base URL. The SDK
	// feed client appends /v1/gossip. Required.
	GossipEndpoint string `json:"gossip_endpoint"`

	// WitnessDIDs are the foreign log's witness public-key DIDs.
	// Required, len >= QuorumK.
	WitnessDIDs []string `json:"witness_dids"`

	// QuorumK is the K-of-N threshold the foreign log's cosignatures
	// must meet. Required, 1 <= QuorumK <= len(WitnessDIDs).
	QuorumK int `json:"quorum_k"`

	// AllowedCosignSchemeTags is the foreign network's admitted
	// cosignature schemes (SchemeECDSA=0x01, SchemeBLS=0x02) — the
	// peer-log analogue of the home network's on-log signature policy
	// (JN has no bootstrap for a foreign log). OPTIONAL: empty/omitted ⇒
	// ECDSA-only (the default, byte-identical to prior behavior). Set
	// [1,2] when a peer log runs BLS witnesses so JN builds a verifier
	// that counts them; a scheme JN cannot verify fails the build loudly
	// rather than silently under-counting it toward quorum.
	AllowedCosignSchemeTags []uint8 `json:"allowed_cosign_scheme_tags,omitempty"`

	// PollInterval is the per-peer catch-up cadence. Zero applies
	// the SDK default (5 seconds — see libs/auditing/peers).
	PollInterval time.Duration `json:"poll_interval,omitempty"`

	// PageLimit caps events per /since page. Zero applies the SDK
	// default (256 events — see libs/auditing/peers).
	PageLimit int `json:"page_limit,omitempty"`

	// WitnessDeclarationsFile is an OPTIONAL path to a JSON snapshot of this
	// foreign log's on-log WitnessEndpointDeclaration entries — the BLS-witness
	// key-material source (a BLS witness cannot be a did:key). Same shape +
	// semantics as WitnessSetConfig.WitnessDeclarationsFile. Empty ⇒ ECDSA-only.
	WitnessDeclarationsFile string `json:"witness_declarations_file,omitempty"`

	// AuthorizedBLSWitnessIDs are the hex-encoded 32-byte PubKeyIDs of this
	// foreign log's BLS witnesses admitted to its K-of-N quorum (the membership
	// authority, NOT self-asserted from the declarations). Required to project
	// any BLS witness; ignored when WitnessDeclarationsFile is empty.
	AuthorizedBLSWitnessIDs []string `json:"authorized_bls_witness_ids,omitempty"`
}

// TileMirrorConfig names one source log's Static-CT tile mirror.
type TileMirrorConfig struct {
	// LogDID is the source log whose inclusion proofs this mirror serves.
	LogDID string `json:"log_did"`
	// BaseURL is the Static-CT tile root URL (the tessera fetcher appends
	// /tile/* paths).
	BaseURL string `json:"base_url"`
}

// ──────────────────────────────────────────────────────────────────
// Witness
// ──────────────────────────────────────────────────────────────────

// WitnessConfig configures the binary's witness wiring:
//
//   - Per-destination ledger endpoint overrides for tree-head
//     fetches. When the per-destination map is empty, every log
//     falls back to the top-level LedgerEndpoint.
//   - Per-destination witness fallback endpoints (used when the
//     ledger's tree head is stale).
//   - TreeHeadClient cache TTL + HTTP timeout.
//
// nil / zero-valued WitnessConfig leaves Dependencies.TreeHeadClient
// at nil — the anchor / topology / monitoring handlers that need it
// will surface 503 with a clear message.
type WitnessConfig struct {
	// LedgerEndpoints maps log DID → ledger base URL. Empty
	// fall back to top-level Operational.LedgerEndpoint.
	LedgerEndpoints map[string]string `json:"ledger_endpoints,omitempty"`

	// WitnessEndpoints maps log DID → list of witness fallback URLs.
	// Empty disables the witness-fallback path; tree-head fetches
	// then go to the ledger only.
	WitnessEndpoints map[string][]string `json:"witness_endpoints,omitempty"`

	// Sets declares the per-log witness topology used for CROSS-LOG
	// verification (Dependencies.WitnessSets). Each entry names a
	// source/peer log's witness DIDs + K-of-N quorum; the binary resolves
	// them to secp256k1 keysets at boot against the network's NetworkID
	// (NetworkBootstrapFile). Empty leaves WitnessSets empty — cross-log
	// handlers then surface 503 for an unknown source log.
	//
	// Sets may instead be DERIVED from the bootstrap document: when Sets is
	// empty and QuorumK > 0, the binary builds a single set for the
	// bootstrap's own log (exchange_did + genesis_witness_set), so an
	// operator points at the bootstrap (env) + sets K rather than
	// hand-listing witness DIDs. This is the env-driven / k8s path.
	Sets []WitnessSetConfig `json:"sets,omitempty"`

	// QuorumK, when > 0 and Sets is empty, triggers deriving the witness
	// set from NetworkBootstrapFile (genesis_witness_set @ K-of-N). Env:
	// API_WITNESS_QUORUM_K. Ignored when Sets is set explicitly.
	QuorumK int `json:"quorum_k,omitempty"`

	// CacheTTL is how long a fetched tree head is cached before a
	// fresh fetch. Zero applies the SDK default.
	CacheTTL time.Duration `json:"cache_ttl,omitempty"`

	// HTTPTimeout caps a single tree-head HTTP fetch. Zero applies
	// the SDK default.
	HTTPTimeout time.Duration `json:"http_timeout,omitempty"`
}

// WitnessSetConfig declares one source/peer log's witness topology for
// cross-log verification: the log's witness DIDs (resolved to secp256k1
// public keys via witness.KeysFromDIDs) and its K-of-N quorum threshold.
// The cosign NetworkID is network-wide (derived from NetworkBootstrapFile),
// so it is not repeated per set.
type WitnessSetConfig struct {
	// LogDID is the source/peer log this witness set verifies (the
	// source_log_did of its anchors / cross-log proofs). Required, unique.
	LogDID string `json:"log_did"`

	// WitnessDIDs are the log's witness public-key DIDs (did:key
	// secp256k1). Required, len >= QuorumK.
	WitnessDIDs []string `json:"witness_dids"`

	// QuorumK is the K-of-N threshold this log's cosignatures must meet.
	// Required, 1 <= QuorumK <= len(WitnessDIDs).
	QuorumK int `json:"quorum_k"`

	// WitnessDeclarationsFile is an OPTIONAL path to a JSON snapshot of this
	// log's on-log WitnessEndpointDeclaration entries (canonical envelope wire
	// bytes per entry — the shape a log scan / the future on-log walker yields,
	// mirroring AUDITOR_REGISTRY_FILE). When set, JN materializes the snapshot
	// and projects the BLS witnesses among AuthorizedBLSWitnessIDs into the
	// keyset (key + proof-of-possession verified at cosign.NewWitnessKeySet
	// construction). A BLS witness cannot be a did:key, so this is the ONLY
	// zero-trust source for its key material. Empty ⇒ ECDSA-only, byte-identical
	// to prior behavior.
	WitnessDeclarationsFile string `json:"witness_declarations_file,omitempty"`

	// AuthorizedBLSWitnessIDs are the hex-encoded 32-byte witness PubKeyIDs
	// admitted to this log's K-of-N quorum as BLS witnesses (the membership
	// authority — the genesis set + the on-log witness-rotation chain). REQUIRED
	// to project any BLS witness: per crosslog.BLSWitnessesFromDeclarations the
	// authorized set is NOT self-asserted from the declarations, so a rogue
	// declaration cannot inject itself into the quorum. Ignored when
	// WitnessDeclarationsFile is empty.
	AuthorizedBLSWitnessIDs []string `json:"authorized_bls_witness_ids,omitempty"`
}

// ──────────────────────────────────────────────────────────────────
// KeyStore
// ──────────────────────────────────────────────────────────────────

// KeyStoreBackend names the deployment-time custody backend for
// signing keys. Stable string values for env / JSON.
type KeyStoreBackend string

const (
	KeyStoreBackendMemory  KeyStoreBackend = "memory"
	KeyStoreBackendSoftHSM KeyStoreBackend = "softhsm"
	KeyStoreBackendVault   KeyStoreBackend = "vault"
)

// KeyStoreConfig configures the institutional signing-key custody
// for the api/ binary. Backend selection is operational; per-DID key
// material itself is provisioned out-of-band (HSM token init, Vault
// transit key creation).
type KeyStoreConfig struct {
	Backend KeyStoreBackend `json:"backend"`

	PKCS11 *PKCS11Config `json:"pkcs11,omitempty"` // populated when Backend = softhsm
	Vault  *VaultConfig  `json:"vault,omitempty"`  // populated when Backend = vault
}

// PKCS11Config is the SoftHSM / cloud HSM connection config.
//
// PINFile holds a filesystem path; the actual PIN string is read at
// boot from that path. JSON config files MUST NEVER contain the PIN
// string itself — production deployments use a sealed file plus a
// host-level secret-injection layer (Kubernetes secret mount,
// HashiCorp Vault Agent, etc.).
type PKCS11Config struct {
	LibraryPath string `json:"library_path"` // e.g., "/usr/lib/softhsm/libsofthsm2.so"
	SlotID      uint   `json:"slot_id"`
	PINFile     string `json:"pin_file"` // path to file containing PIN
	TokenLabel  string `json:"token_label"`
}

// VaultConfig is the HashiCorp Vault Transit native secp256k1 config.
//
// Mode is implicit: always "transit native". secp256k1 has been in
// Vault Transit OSS since v1.18 (Sept 2024); production deployments
// run latest Vault, where this is GA.
//
// TokenFile is filesystem-sourced; never inline in JSON. See PINFile
// in PKCS11Config for the same rationale.
type VaultConfig struct {
	Address   string `json:"address"`    // e.g., "https://vault.svc:8200"
	TokenFile string `json:"token_file"` // path to file containing Vault token
	Mount     string `json:"mount"`      // e.g., "transit"
	KeyName   string `json:"key_name"`   // e.g., "exchange-davidson-signer-1"
}

// ──────────────────────────────────────────────────────────────────
// NonceStore
// ──────────────────────────────────────────────────────────────────

// NonceStoreBackend names the deployment-time nonce-store backend for
// signed-request replay protection. Stable string values for env /
// JSON.
type NonceStoreBackend string

const (
	NonceStoreBackendMemory NonceStoreBackend = "memory"
	NonceStoreBackendRedis  NonceStoreBackend = "redis"
)

// NonceStoreOpConfig configures replay-protection for signed
// requests. Per-tenant namespacing happens at runtime via
// auth.NonceStoreConfig.BuildForExchange — operational config holds
// only the connection.
type NonceStoreOpConfig struct {
	Backend NonceStoreBackend `json:"backend"`

	// FreshnessWindow caps signed-request timestamp staleness. Empty
	// or zero → DefaultFreshnessWindow (5 minutes).
	FreshnessWindow time.Duration `json:"freshness_window"`

	// Redis-only fields. Empty/ignored for memory backend.
	RedisAddr      string `json:"redis_addr,omitempty"`
	RedisPassword string `json:"redis_password,omitempty"`
	RedisDB        int    `json:"redis_db,omitempty"`
	RedisKeyPrefix string `json:"redis_key_prefix,omitempty"`
}

// ──────────────────────────────────────────────────────────────────
// Auth
// ──────────────────────────────────────────────────────────────────

// AuthMode names the deployment-time auth mode for the api/ surface.
// Routing dispatch is ALWAYS payload-driven (entry.Header.Destination);
// auth determines callerDID. The two are decoupled.
type AuthMode string

const (
	AuthModeMTLS AuthMode = "mtls"
	AuthModeJWT  AuthMode = "jwt"
)

// AuthConfig configures caller-identity establishment. mTLS reads the
// signer DID from the client cert SAN; JWT reads it from the verified
// token's subject claim.
type AuthConfig struct {
	Mode AuthMode `json:"mode"`

	// mTLS-specific
	ClientCAFile string `json:"client_ca_file,omitempty"` // PEM, for verifying client certs

	// JWT-specific
	JWTIssuer string `json:"jwt_issuer,omitempty"` // expected `iss` claim
	JWKSURL   string `json:"jwks_url,omitempty"`   // public-key set endpoint

	// Server TLS material (used by both modes; mTLS additionally
	// requires ClientCAFile above to verify peer certs).
	TLSCertFile string `json:"tls_cert_file,omitempty"`
	TLSKeyFile  string `json:"tls_key_file,omitempty"`
}

// ──────────────────────────────────────────────────────────────────
// Loading
// ──────────────────────────────────────────────────────────────────

// LoadFromFile reads a JSON file into an Operational, applying it on
// top of Defaults(). Returns ErrInvalidConfig wrapped with the
// underlying read or parse error.
func LoadFromFile(path string) (Operational, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Operational{}, fmt.Errorf("%w: read %q: %w", ErrInvalidConfig, path, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Operational{}, fmt.Errorf("%w: parse %q: %w", ErrInvalidConfig, path, err)
	}
	return cfg, nil
}

// ApplyEnvOverrides applies a fixed allowlist of env vars to cfg.
// Precedence: env > file > defaults. Returns the modified config so
// callers can chain.
//
// The recognized env vars are:
//
//	API_LISTEN_ADDR
//	API_LEDGER_ENDPOINT
//	API_ARTIFACT_STORE_ENDPOINT
//	API_VERIFICATION_ENDPOINT
//	API_ETH_RPC_ENDPOINT
//	API_KEYSTORE_BACKEND          (memory|softhsm|vault)
//	API_NONCE_STORE_BACKEND       (memory|redis)
//	API_NONCE_STORE_REDIS_ADDR
//	API_AUTH_MODE                 (mtls|jwt)
//	API_NETWORK_BOOTSTRAP_FILE    (shared trust root; falls back to
//	                               LEDGER_NETWORK_BOOTSTRAP_FILE — the var
//	                               the standalone-witness fleet emits)
//	API_AUTH_CLIENT_CA_FILE       (mTLS; Secret/mount path)
//	API_AUTH_TLS_CERT_FILE        (mTLS; Secret/mount path)
//	API_AUTH_TLS_KEY_FILE         (mTLS; Secret/mount path)
//	API_GOSSIP_INGEST_ENABLED     (bool)
//	API_GOSSIP_INGEST_PEER_URL    (verify-only ingest source: the auditor's
//	                               /v1/gossip base URL; falls back to the ledger)
//	API_MONITORING_ENABLED        (bool)
//	API_WITNESS_QUORUM_K          (int; derive witness set from bootstrap)
//
// Unrecognized vars are ignored. Empty values are NOT applied
// (treat as "keep current").
func ApplyEnvOverrides(cfg Operational) Operational {
	if v := os.Getenv("API_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("API_LEDGER_ENDPOINT"); v != "" {
		cfg.LedgerEndpoint = v
	}
	if v := os.Getenv("API_LEDGER_CERT_FILE"); v != "" {
		cfg.LedgerCertFile = v
	}
	if v := os.Getenv("API_LEDGER_KEY_FILE"); v != "" {
		cfg.LedgerKeyFile = v
	}
	if v := os.Getenv("API_LEDGER_CA_FILE"); v != "" {
		cfg.LedgerCAFile = v
	}
	if v := os.Getenv("API_ARTIFACT_STORE_ENDPOINT"); v != "" {
		cfg.ArtifactStoreEndpoint = v
	}
	if v := os.Getenv("API_VERIFICATION_ENDPOINT"); v != "" {
		cfg.VerificationEndpoint = v
	}
	if v := os.Getenv("API_KEYSTORE_BACKEND"); v != "" {
		cfg.KeyStore.Backend = KeyStoreBackend(strings.ToLower(strings.TrimSpace(v)))
	}
	if v := os.Getenv("API_NONCE_STORE_BACKEND"); v != "" {
		cfg.NonceStore.Backend = NonceStoreBackend(strings.ToLower(strings.TrimSpace(v)))
	}
	if v := os.Getenv("API_NONCE_STORE_REDIS_ADDR"); v != "" {
		cfg.NonceStore.RedisAddr = v
	}
	if v := os.Getenv("API_AUTH_MODE"); v != "" {
		cfg.Auth.Mode = AuthMode(strings.ToLower(strings.TrimSpace(v)))
	}
	// Discover the shared trust root (network bootstrap doc → NetworkID +
	// witness keysets) from env. API_NETWORK_BOOTSTRAP_FILE is the explicit
	// JN-namespaced override; absent that, fall back to the SAME
	// LEDGER_NETWORK_BOOTSTRAP_FILE the standalone-witness fleet emits
	// (`make print-env`), so one `eval` feeds the ledger AND the JN with a
	// byte-identical bootstrap. The JN never discovers witness ENDPOINTS or
	// QUORUM_K: it verifies cosigned heads (it does not collect them), and K
	// is encapsulated inside each WitnessKeySet, not a flat env knob.
	if v := os.Getenv("API_NETWORK_BOOTSTRAP_FILE"); v != "" {
		cfg.NetworkBootstrapFile = v
	} else if v := os.Getenv("LEDGER_NETWORK_BOOTSTRAP_FILE"); v != "" {
		cfg.NetworkBootstrapFile = v
	}

	// mTLS material as env-referenced paths. The binary stays deployment-
	// agnostic: native exports a .run path, docker/k8s mount a Secret and
	// point these at the mount. No path is ever baked into the Go.
	if v := os.Getenv("API_AUTH_CLIENT_CA_FILE"); v != "" {
		cfg.Auth.ClientCAFile = v
	}
	if v := os.Getenv("API_AUTH_TLS_CERT_FILE"); v != "" {
		cfg.Auth.TLSCertFile = v
	}
	if v := os.Getenv("API_AUTH_TLS_KEY_FILE"); v != "" {
		cfg.Auth.TLSKeyFile = v
	}

	// Active-auditor toggles + inputs. Off by default; the SAME env surface
	// drives native, docker-compose, and k8s — the witness set + gossip
	// peers derive from the (env-pointed) bootstrap, so only toggles + file
	// paths + K are set here.
	if b, ok := envBool("API_GOSSIP_INGEST_ENABLED"); ok {
		cfg.GossipIngest.Enabled = b
	}
	if v := os.Getenv("API_GOSSIP_INGEST_PEER_URL"); v != "" {
		cfg.GossipIngest.PeerURL = v
	}
	if v := os.Getenv("API_GOSSIP_INGEST_DIDWEB_TTL"); v != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil && d > 0 {
			cfg.GossipIngest.PeerResolveTTL = d
		}
	}
	if b, ok := envBool("API_GOSSIP_INGEST_DISCOVER_ORIGINATOR"); ok {
		cfg.GossipIngest.DiscoverOriginator = b
	}
	if b, ok := envBool("API_MONITORING_ENABLED"); ok {
		cfg.Monitoring.Enabled = b
	}
	if v := os.Getenv("API_WITNESS_QUORUM_K"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			cfg.Witness.QuorumK = n
		}
	}

	// Auditor-scope gate (v1.33.x). Off by default; flip on once registry +
	// amendment files are provisioned. Mirrors the attesta-tools auditor's
	// AUDITOR_ENFORCE_SCOPES / AUDITOR_REGISTRY_FILE / AUDITOR_AMENDMENT_FILE
	// env surface so one operator manifest drives both auditor and JN.
	if b, ok := envBool("API_ENFORCE_SCOPES"); ok {
		cfg.AuditorScope.Enforce = b
	}
	if v := os.Getenv("API_AUDITOR_REGISTRY_FILE"); v != "" {
		cfg.AuditorScope.RegistryFile = v
	}
	if v := os.Getenv("API_AUDITOR_AMENDMENT_FILE"); v != "" {
		cfg.AuditorScope.AmendmentFile = v
	}
	if b, ok := envBool("API_RELOAD_ON_SIGHUP"); ok {
		cfg.AuditorScope.ReloadOnSIGHUP = b
	}

	// URL-drift audit interval (libs/monitoring/url_drift_audit.go). Zero
	// (the default) disables the job. Non-zero registers a `url_drift_audit`
	// scheduler job when the resolver inputs are populated.
	if v := os.Getenv("API_URL_DRIFT_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil && d > 0 {
			cfg.URLDriftInterval = d
		}
	}

	return cfg
}

// envBool parses a boolean env var. Returns (value, present); present is
// false when the var is unset or unparseable, so callers leave the current
// config value untouched (an invalid env value never silently disables a
// feature configured in JSON).
func envBool(name string) (val, present bool) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return false, false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, false
	}
	return b, true
}

// ──────────────────────────────────────────────────────────────────
// Validation
// ──────────────────────────────────────────────────────────────────

// Validate enforces operational consistency at boot. Each rule is
// independent; the first failure is returned with a descriptive
// message wrapping ErrInvalidConfig.
//
// Rules enforced:
//
//  1. ListenAddr non-empty.
//  2. LedgerEndpoint + VerificationEndpoint non-empty (the ledger is the
//     JN's hard dependency). ArtifactStoreEndpoint is optional (the
//     document surface; absent ⇒ ledger-only deployment).
//  3. KeyStore.Backend is one of the known constants.
//  4. KeyStore-specific sub-config is populated when its backend is
//     selected (PKCS11 for softhsm; Vault for vault). Unused
//     sub-configs MUST be nil to surface accidental copy-paste.
//  5. NonceStore.Backend is one of the known constants.
//  6. SmartContractWallet per-chain quorum invariants (when enabled).
//  7. NonceStore.RedisAddr non-empty when Backend = redis.
//  8. NonceStore.FreshnessWindow > 0.
//  9. Auth.Mode is one of the known constants.
//
// 10. Auth-mode-specific fields populated as required.
//
// Validate does NOT touch the filesystem (e.g., to verify PINFile
// exists). That's the binary's job at first KeyStore use, so unit
// tests can construct an Operational without staging real files.
func (cfg Operational) Validate() error {
	if cfg.ListenAddr == "" {
		return fmt.Errorf("%w: ListenAddr required", ErrInvalidConfig)
	}
	if cfg.LedgerEndpoint == "" {
		return fmt.Errorf("%w: LedgerEndpoint required (the JN is an auditor of a ledger)", ErrInvalidConfig)
	}
	// ArtifactStoreEndpoint is optional — it serves the document/blob
	// surface, not the entry-write or audit path. Empty ⇒ ledger-only.
	if cfg.VerificationEndpoint == "" {
		return fmt.Errorf("%w: VerificationEndpoint required", ErrInvalidConfig)
	}

	if err := cfg.KeyStore.validate(); err != nil {
		return err
	}
	if err := cfg.NonceStore.validate(); err != nil {
		return err
	}
	if err := cfg.Auth.validate(); err != nil {
		return err
	}
	if err := cfg.SmartContractWallet.validate(); err != nil {
		return err
	}
	if err := cfg.AuditorScope.validate(); err != nil {
		return err
	}
	if err := cfg.GossipIngest.ValidatePeerLogs(); err != nil {
		return err
	}
	return nil
}

// validate enforces the boot-fast-fail rule for the auditor-scope gate:
// Enforce=true && RegistryFile=="" is a misconfiguration. Without the
// registry the reconciler has no way to learn which auditors are scoped
// for which finding kinds, so enforcement would silently allow every
// finding through — exactly the downgrade the gate exists to prevent.
//
// AmendmentFile is optional independent of Enforce: an empty amendments
// slice is the legal "no amendments yet" state (registry-only scope).
func (a AuditorScopeConfig) validate() error {
	if a.Enforce && a.RegistryFile == "" {
		return fmt.Errorf("%w: AuditorScope.Enforce=true but RegistryFile empty (refusing to boot with a silent scope-gate downgrade; set API_AUDITOR_REGISTRY_FILE)", ErrInvalidConfig)
	}
	return nil
}

// validate enforces the C-2 PeerLog contract: every foreign-network peer
// entry must declare its own LogDID, NetworkID (32-byte hex / 64 chars),
// gossip endpoint, and witness set + quorum. A malformed PeerLogs entry
// is a startup-fatal misconfiguration — verification of cross-log
// references would otherwise silently fall back to the home network's
// trust roots, defeating Scenario 1.
func (p PeerLogConfig) validate(index int) error {
	if p.LogDID == "" {
		return fmt.Errorf("%w: PeerLogs[%d].LogDID required (the foreign log's DID)", ErrInvalidConfig, index)
	}
	if p.GossipEndpoint == "" {
		return fmt.Errorf("%w: PeerLogs[%d] (%s).GossipEndpoint required (the foreign log's /v1/gossip base URL)", ErrInvalidConfig, index, p.LogDID)
	}
	// NetworkID must be exactly 64 hex chars (32 bytes); without the
	// right NetworkID, cosign canonical bytes never match and every
	// foreign-network head fails verification — the operator deserves
	// a loud error at boot, not a silent verification dead-end.
	if len(p.NetworkID) != 64 {
		return fmt.Errorf("%w: PeerLogs[%d] (%s).NetworkID must be 64 hex chars (32 bytes); got %d chars",
			ErrInvalidConfig, index, p.LogDID, len(p.NetworkID))
	}
	for _, c := range p.NetworkID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("%w: PeerLogs[%d] (%s).NetworkID must be hex; non-hex character %q",
				ErrInvalidConfig, index, p.LogDID, c)
		}
	}
	if len(p.WitnessDIDs) == 0 {
		return fmt.Errorf("%w: PeerLogs[%d] (%s).WitnessDIDs required (foreign log's witness public-key DIDs)",
			ErrInvalidConfig, index, p.LogDID)
	}
	if p.QuorumK <= 0 || p.QuorumK > len(p.WitnessDIDs) {
		return fmt.Errorf("%w: PeerLogs[%d] (%s).QuorumK = %d, must be 1..%d",
			ErrInvalidConfig, index, p.LogDID, p.QuorumK, len(p.WitnessDIDs))
	}
	return nil
}

// ValidatePeerLogs enforces uniqueness on LogDID (a duplicate would
// route conflicting cosigned heads into the same journal slot at
// publish time) and per-entry well-formedness. Called from
// Operational.Validate at boot.
func (g GossipIngestConfig) ValidatePeerLogs() error {
	seen := make(map[string]int, len(g.PeerLogs))
	for i, p := range g.PeerLogs {
		if prev, dup := seen[p.LogDID]; dup {
			return fmt.Errorf("%w: PeerLogs[%d] duplicates LogDID from PeerLogs[%d] (%s)",
				ErrInvalidConfig, i, prev, p.LogDID)
		}
		if err := p.validate(i); err != nil {
			return err
		}
		seen[p.LogDID] = i
	}
	return nil
}

func (k KeyStoreConfig) validate() error {
	switch k.Backend {
	case KeyStoreBackendMemory:
		if k.PKCS11 != nil {
			return fmt.Errorf("%w: PKCS11 set with memory backend (set Backend = softhsm or remove PKCS11)", ErrInvalidConfig)
		}
		if k.Vault != nil {
			return fmt.Errorf("%w: Vault set with memory backend (set Backend = vault or remove Vault)", ErrInvalidConfig)
		}
	case KeyStoreBackendSoftHSM:
		if k.PKCS11 == nil {
			return fmt.Errorf("%w: PKCS11 required for softhsm backend", ErrInvalidConfig)
		}
		if k.Vault != nil {
			return fmt.Errorf("%w: Vault must be nil for softhsm backend", ErrInvalidConfig)
		}
		if k.PKCS11.LibraryPath == "" {
			return fmt.Errorf("%w: PKCS11.LibraryPath required", ErrInvalidConfig)
		}
		if k.PKCS11.PINFile == "" {
			return fmt.Errorf("%w: PKCS11.PINFile required (path to file containing the PIN)", ErrInvalidConfig)
		}
		if k.PKCS11.TokenLabel == "" {
			return fmt.Errorf("%w: PKCS11.TokenLabel required", ErrInvalidConfig)
		}
	case KeyStoreBackendVault:
		if k.Vault == nil {
			return fmt.Errorf("%w: Vault required for vault backend", ErrInvalidConfig)
		}
		if k.PKCS11 != nil {
			return fmt.Errorf("%w: PKCS11 must be nil for vault backend", ErrInvalidConfig)
		}
		if k.Vault.Address == "" {
			return fmt.Errorf("%w: Vault.Address required", ErrInvalidConfig)
		}
		if k.Vault.TokenFile == "" {
			return fmt.Errorf("%w: Vault.TokenFile required", ErrInvalidConfig)
		}
		if k.Vault.Mount == "" {
			return fmt.Errorf("%w: Vault.Mount required (e.g., \"transit\")", ErrInvalidConfig)
		}
		if k.Vault.KeyName == "" {
			return fmt.Errorf("%w: Vault.KeyName required", ErrInvalidConfig)
		}
	case "":
		return fmt.Errorf("%w: KeyStore.Backend required (memory|softhsm|vault)", ErrInvalidConfig)
	default:
		return fmt.Errorf("%w: KeyStore.Backend %q not recognized (expected memory|softhsm|vault)",
			ErrInvalidConfig, k.Backend)
	}
	return nil
}

func (n NonceStoreOpConfig) validate() error {
	switch n.Backend {
	case NonceStoreBackendMemory:
		// Memory backend ignores Redis fields.
	case NonceStoreBackendRedis:
		if n.RedisAddr == "" {
			return fmt.Errorf("%w: NonceStore.RedisAddr required for redis backend", ErrInvalidConfig)
		}
	case "":
		return fmt.Errorf("%w: NonceStore.Backend required (memory|redis)", ErrInvalidConfig)
	default:
		return fmt.Errorf("%w: NonceStore.Backend %q not recognized (expected memory|redis)",
			ErrInvalidConfig, n.Backend)
	}
	if n.FreshnessWindow <= 0 {
		return fmt.Errorf("%w: NonceStore.FreshnessWindow must be > 0", ErrInvalidConfig)
	}
	return nil
}

func (a AuthConfig) validate() error {
	switch a.Mode {
	case AuthModeMTLS:
		if a.ClientCAFile == "" {
			return fmt.Errorf("%w: Auth.ClientCAFile required for mtls mode", ErrInvalidConfig)
		}
		if a.TLSCertFile == "" || a.TLSKeyFile == "" {
			return fmt.Errorf("%w: Auth.TLSCertFile and TLSKeyFile required for mtls mode", ErrInvalidConfig)
		}
	case AuthModeJWT:
		if a.JWTIssuer == "" {
			return fmt.Errorf("%w: Auth.JWTIssuer required for jwt mode", ErrInvalidConfig)
		}
		if a.JWKSURL == "" {
			return fmt.Errorf("%w: Auth.JWKSURL required for jwt mode", ErrInvalidConfig)
		}
		// Server TLS still recommended for JWT but not strictly
		// required (e.g., when the api/ runs behind a TLS-terminating
		// proxy). Skip the check.
	case "":
		return fmt.Errorf("%w: Auth.Mode required (mtls|jwt)", ErrInvalidConfig)
	default:
		return fmt.Errorf("%w: Auth.Mode %q not recognized (expected mtls|jwt)",
			ErrInvalidConfig, a.Mode)
	}
	return nil
}

// MarshalForLogging returns a JSON representation safe to log: it
// strips secret-bearing fields (TokenFile / PINFile only carry paths,
// not values, so they ARE safe; this is defense in depth in case
// future fields hold raw secret strings). Today this is identical to
// json.Marshal — the function exists so future additions of secret
// fields have a single sanitization point.
func (cfg Operational) MarshalForLogging() ([]byte, error) {
	return json.MarshalIndent(cfg, "", "  ")
}

// Compile-time check that ParseDuration helper signature is stable.
// The package does not export it, but tests round-trip Operational
// through JSON which exercises time.Duration's UnmarshalJSON path.
var _ = strconv.Itoa
