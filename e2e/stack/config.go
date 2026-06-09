// Package stack realises a topology.StackSpec into a running, persisted baseproof
// e2e stack: shared infra (postgres + object store), then per network a witness
// fleet, a ledger, auditors, and a JN enforcer. config.go resolves the images and
// derives the addressable per-network config (names + host ports) from a spec.
package stack

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/clearcompass-ai/judicial-network/e2e/topology"
)

// Shared, harness-chosen identifiers (baseproof-branded). The tooling fleet
// images (ledger/witness/auditor) now publish under ghcr.io/baseproof/tooling;
// JN's own images stay under ghcr.io/clearcompass-ai/judicial-network, and
// did:attesta: DIDs are intentionally left as published. Everything the harness
// itself owns uses the baseproof name.
const (
	pgUser     = "baseproof"
	pgPassword = "baseproof"
	caCN       = "baseproof-dev-ca"
	netName    = "baseproof-e2e" // gen-fixtures -network-name
	bucket     = "baseproof-bytes"
	callerDID  = "did:web:baseproof:user:cli" // client-cert URI SAN (harness identity)

	// In-container mount points the harness controls.
	mntFixtures = "/run/fixtures"
	mntCerts    = "/run/certs"
	mntKeys     = "/keys"
	mntOut      = "/out"

	tileDir = "/var/lib/ledger/tiles"

	pgDBDefault = "baseproof_test" // POSTGRES_DB (the single-network ledger DB)

	ghcr    = "ghcr.io/clearcompass-ai"   // JN's own image namespace (unchanged)
	tooling = "ghcr.io/baseproof/tooling" // relocated tooling fleet images
)

// uidGID returns the host uid:gid so image entrypoints write fixtures we can read.
func uidGID() string { return fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()) }

// Tunable intervals (env-overridable), matching the proven harness defaults.
func sequencerInterval() string      { return env("E2E_SEQUENCER_INTERVAL", "250ms") }
func auditorPollInterval() string    { return env("E2E_AUDITOR_POLL_INTERVAL", "2s") }
func auditorHorizonInterval() string { return env("E2E_AUDITOR_HORIZON_INTERVAL", "5s") }
func auditorScanInterval() string    { return env("E2E_AUDITOR_SCAN_INTERVAL", "5s") }
func auditHorizonSamples() string    { return env("E2E_AUDIT_RANDOM", "16") }
func ledgerLogLevel() string         { return env("E2E_LEDGER_LOG_LEVEL", "") }

// jnBestEffort, when truthy (E2E_JN_BEST_EFFORT=1), downgrades a JN bring-up
// failure from fatal to a loud warning so `up` still persists the stack — an
// escape hatch to validate the open ledger/auditor/tools path in isolation.
// `e2e up` now BUILDS the JN image from the local working tree (cmd/e2e
// ensureImages), so the enforcer carries the branch's code (incl. the open-HTTPS
// JN→ledger leg) and should come up cleanly — this flag should rarely be needed.
// Default off: the JN is the write gate, so its failure is fatal in normal
// operation.
func jnBestEffort() bool {
	switch strings.ToLower(env("E2E_JN_BEST_EFFORT", "")) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// readerEnabled (E2E_READER=1) launches a PG-off ledger-reader read front per
// network at `up`, so the federation.proof.pgoff arm has a real object-store-
// backed front to prove against. Default off: the read front is an extra
// container per network the base stack does not need.
func readerEnabled() bool {
	switch strings.ToLower(env("E2E_READER", "")) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// walRetentionBufferEnv reads E2E_WAL_RETENTION_BUFFER — the WAL retention GC
// margin in SEQUENCES that turns GC on for the verify.walgc arm. 0/unset ⇒ GC
// stays off (the production-safe default).
func walRetentionBufferEnv() uint64 {
	if v := strings.TrimSpace(env("E2E_WAL_RETENTION_BUFFER", "")); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// Images are the container images, each overridable via E2E_*_IMAGE.
type Images struct {
	Postgres, Seaweed, Ledger, Witness, Auditor, Aggregator, JN string
}

// ResolveImages reads the image set from the environment. E2E_TESSERA=upstream
// selects the published Google-tessera ledger variant.
func ResolveImages() Images {
	suffix := ""
	if strings.EqualFold(env("E2E_TESSERA", "fork"), "upstream") {
		suffix = "-upstream"
	}
	return Images{
		Postgres: env("E2E_POSTGRES_IMAGE", "postgres:16-alpine"),
		Seaweed:  env("E2E_SEAWEED_IMAGE", "chrislusf/seaweedfs:3.71"),
		// ledger + auditor carry the open-HTTPS server / open-client postures. The
		// fleet is pinned to the tooling 0.0.36 release — a superset of 0.0.23
		// (receipt fix B: GET /v1/receipt/proof/{seq} binds to its OWN
		// covering-checkpoint head, so a SETTLED entry far below the horizon verifies
		// against a per-checkpoint-delta ReceiptRoot; PLUS Phase 1 cold reads: the
		// PG-free read front and the per-size-checkpoint (1.1a), receipt-commitment
		// (1.2a) and witness-rotation (1.2b) archives those proofs reconstruct from),
		// 0.0.24 (adds /ledger-reader — the PG-OFF arm's read front), Phase 2 (WAL
		// retention GC [off unless LEDGER_WAL_RETENTION_BUFFER is set], incremental SMT
		// tiling, and the read-cost-bounding QueryBy* keyset pagination + covering
		// indexes + immutable receipt cache), 0.0.29 (the read front reconstructs
		// INCLUSION proofs + /raw seq→hash from the OBJECT STORE alone — the writer
		// ships tessera log tiles + entry bundles to S3, so the PG-off reader needs no
		// filesystem shared with the writer; the reader also serves HTTPS + reads the
		// writer's LEDGER_* env; hardens the tile-ship cursor so a new network never
		// bulk-ships), 0.0.30 (the read front now serves the RECEIPT + BURN proof legs
		// PG-free: a bucketed checkpoint-size index enumerates published checkpoints so
		// the receipt head resolves with no Postgres, and the per-size checkpoint, size
		// index, and receipt-commitment archives publish durable-before-horizon — so a
		// FULL v2 proof verifies offline against the PG-off reader, not just the
		// inclusion+SMT legs), 0.0.31 (the read front now DERIVES the per-log
		// object-store namespace the writer prepends — bytestore.NamespaceForLog(LogDID)
		// — so the cold reader actually resolves that horizon + those archives instead
		// of reading an empty namespace at the bucket root; without it every substrate
		// read 404s and /v1/tree/horizon 503s), and 0.0.32 (the read front now serves
		// GET /v1/network/bootstrap — the genesis CONFIG the v2 gather SHA-256-checks
		// against the trust root — from LEDGER_NETWORK_BOOTSTRAP_FILE, and puts a
		// host-reachable URL in the /raw 302 via LEDGER_BYTE_STORE_PUBLIC_BASE_URL
		// instead of the in-network S3 endpoint; the LAST two addressing gaps for a full
		// offline proof against the PG-off reader), 0.0.33 (the writer no longer OOMs
		// under sustained load — the in-memory SMT node tail is bounded to the un-tiled gap:
		// the checkpoint loop prunes durably-tiled nodes AND the builder drops intra-batch
		// orphan nodes via the SDK's OverlayNodeStore.ReachableMutations, so the ledger heap
		// is O(throughput × checkpoint-interval), not O(history) — the 300k-backfill OOM),
		// and 0.0.36 (that bounded tail's durable-set prune no longer STALLS tiling: re-emitting
		// a checkpoint's tile re-reads unchanged interiors the prune evicted, which the tile
		// store cannot address by interior hash — so the checkpoint held "smt_tiles_not_durable:
		// interior node missing". The writer now threads the prior committed root into the SDK's
		// incremental emitter [v0.0.3-rc6 BuildDirtyTiles fromRoot warm-walk], warming the
		// same-position prior tile before each re-emit so those interiors resolve; the tail stays
		// bounded AND tiling progresses — the prerequisite for the 300k cold-serve backfill).
		// 0.0.39 = the flat-to-20M build: rc8 (node-bounded TileCache) + tail orphan
		// prune (LEDGER_TAIL_GC_PRUNE — memory flat) + incremental WAL retention-GC
		// (throughput flat regardless of LEDGER_WAL_RETENTION_BUFFER) + the tail-GC
		// audit (LEDGER_TAIL_GC_AUDIT). v0.1.1 then fixed the pruned-tail tiling STALL
		// AT SCALE: the rc7/rc8 memory cap had re-bounded the emit walk's read-through,
		// so past ~172k entries it evicted a dirty band's clean interior mid-walk and
		// the checkpoint held "smt_tiles_not_durable: interior node missing" (the SMT
		// horizon froze while integration ran on). v0.1.1 tiles each checkpoint through
		// a FRESH UNBOUNDED per-emit store, so the cap stays on the long-lived proof
		// path and the horizon advances in lockstep with integration. v0.1.2 = v0.1.1
		// plus baseproof rc9 (test-only) + deploy/config-injection (Helm, non-root,
		// std-path certs) — NO change to the SMT commit/integration path.
		//
		// v0.1.4 closes the LEAF-LOSS residue v0.1.1's warm-walk did not: a compressed
		// pointer can reach a band INTERIOR without its tile top, and tiles are keyed by
		// TOP, so that interior was unfetchable — the builder's SetLeaves faulted
		// "missing node (referenced by ancestor)", silently demoted the entry to PathD,
		// and the committed (cosigned) root OMITTED its leaf, served thereafter as
		// non-membership. baseproof v0.0.4-rc2 adds a node→owning-tile-top index
		// consulted on a TiledNodeStore.Get miss (any node resolvable by hash,
		// regardless of walk order) AND makes ProcessBatch HALT on the fault instead of
		// dropping the leaf; the ledger builds/persists that index at tile-emit time
		// (LEDGER_NODE_INDEX, default on) with a backfill for recovery, plus a per-batch
		// commit-integrity diagnostic (LEDGER_TRACE_COMMIT) and a reusable tile-miss
		// classifier. Witness + auditor are the SAME v0.1.4 coordinated fleet build;
		// override via E2E_*_IMAGE.
		Ledger:     env("E2E_LEDGER_IMAGE", tooling+"/ledger:0.1.4"+suffix),
		Witness:    env("E2E_WITNESS_IMAGE", tooling+"/witness:0.1.4"),
		Auditor:    env("E2E_AUDITOR_IMAGE", tooling+"/auditor:0.1.4"),
		Aggregator: env("E2E_AGGREGATOR_IMAGE", ghcr+"/judicial-network/aggregator:latest"),
		JN:         env("E2E_JN_IMAGE", ghcr+"/judicial-network:latest"),
	}
}

// All returns the images as a slice (for the pull step).
func (im Images) All() []string {
	return []string{im.Postgres, im.Seaweed, im.Ledger, im.Witness, im.Auditor, im.Aggregator, im.JN}
}

// NetConfig is the resolved, addressable config for one network in the stack.
type NetConfig struct {
	Spec       topology.NetworkSpec
	Tuning     topology.Tuning
	Prefix     string // container-name prefix, e.g. "baseproof-a3f" or "baseproof-a3f-federal"
	Network    string // shared docker network, e.g. "baseproof-a3f"
	DB         string // per-network ledger database, e.g. "baseproof_test" / "baseproof_federal"
	LogDIDSeed string // -log-did passed to gen-fixtures
	LogDID     string // resolved exchange_did from the bootstrap (filled after fixtures)

	LedgerPort     int
	ReaderPort     int // PG-off read front (ledger-reader) host port; 0 when not launched
	JNPort         int
	AggregatorPort int
	AuditorPorts   []int
	AggDB          string // per-network aggregator projection DB (when HasAggregator)
	Bucket         string // per-network object-store bucket — isolates each log's S3
	// namespace so the ledger's fixed-name objects (the cosigned-checkpoint horizon,
	// and any other non-content-addressed key) can never overlap across networks that
	// would otherwise share one bucket (the "last writer clobbers the horizon" class).
	Single bool // the stack has exactly one network (names/DB collapse)
}

// Name returns the container name for a service in this network.
func (c NetConfig) Name(svc string) string { return c.Prefix + "-" + svc }

// GossipDB is the per-auditor gossip database name. It MUST be unique across the
// whole stack (all networks share one postgres), so multi-network names carry the
// network segment; the single-network name stays the familiar auditor_gossip_N.
func (c NetConfig) GossipDB(idx int) string {
	if c.Single {
		return fmt.Sprintf("auditor_gossip_%d", idx)
	}
	return fmt.Sprintf("gossip_%s_%d", c.Spec.Name, idx)
}

// dsn builds a postgres DSN for the shared pg container + a database.
func dsn(pgContainer, db string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:5432/%s?sslmode=disable", pgUser, pgPassword, pgContainer, db)
}

// Port plan. Each network's services bind the same container ports (8080/8443/8088)
// to distinct HOST ports so multiple networks coexist. Strides keep them apart.
const (
	ledgerPortBase     = 8080
	readerPortBase     = 8081 // PG-off read front, one per network (free slot below the auditor block)
	jnPortBase         = 8443
	auditorPortBase    = 8088
	aggregatorPortBase = 8092
	perNetworkStride   = 20 // host-port gap between networks
)

// DeriveNetConfigs derives the per-network addressable config for a spec under a
// run id. For a single-network stack the names collapse to "baseproof-{id}-{svc}"
// and the database is the plain baseproof_test, reproducing the throughput stack;
// for multiple networks each gets a "{netname}" segment, its own database, and a
// strided host-port block.
func DeriveNetConfigs(spec topology.StackSpec, runID string) []NetConfig {
	// E2E_WAL_RETENTION_BUFFER turns WAL GC on for the verify.walgc arm without
	// editing a preset (spec is a value — this override is local to this stack).
	if b := walRetentionBufferEnv(); b > 0 {
		spec.Tuning.WALRetentionBuffer = b
	}
	network := "baseproof-" + runID
	single := len(spec.Networks) == 1
	out := make([]NetConfig, 0, len(spec.Networks))
	for i, n := range spec.Networks {
		prefix := network
		db := "baseproof_test"
		seed := "did:web:state:tn:davidson"
		// Single-network keeps the familiar shared bucket; multi-network gives each
		// network its OWN bucket so per-log object-store namespaces never overlap.
		bkt := bucket
		if !single {
			prefix = network + "-" + n.Name
			db = "baseproof_" + n.Name
			seed = "did:web:baseproof:" + n.Name
			bkt = bucket + "-" + n.Name
		}
		auditorPorts := make([]int, n.Auditors)
		for a := 0; a < n.Auditors; a++ {
			auditorPorts[a] = auditorPortBase + i*perNetworkStride + a
		}
		aggDB := "aggregator"
		if !single {
			aggDB = "aggregator_" + n.Name
		}
		out = append(out, NetConfig{
			Spec:           n,
			Tuning:         spec.Tuning,
			Prefix:         prefix,
			Network:        network,
			DB:             db,
			LogDIDSeed:     seed,
			LedgerPort:     ledgerPortBase + i*perNetworkStride,
			ReaderPort:     readerPortBase + i*perNetworkStride,
			JNPort:         jnPortBase + i*perNetworkStride,
			AggregatorPort: aggregatorPortBase + i*perNetworkStride,
			AuditorPorts:   auditorPorts,
			AggDB:          aggDB,
			Bucket:         bkt,
			Single:         single,
		})
	}
	return out
}
