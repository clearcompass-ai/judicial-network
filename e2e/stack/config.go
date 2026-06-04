// Package stack realises a topology.StackSpec into a running, persisted baseproof
// e2e stack: shared infra (postgres + object store), then per network a witness
// fleet, a ledger, auditors, and a JN enforcer. config.go resolves the images and
// derives the addressable per-network config (names + host ports) from a spec.
package stack

import (
	"fmt"
	"os"
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
func auditHorizonSamples() string    { return env("E2E_AUDIT_RANDOM", "16") }
func ledgerLogLevel() string         { return env("E2E_LEDGER_LOG_LEVEL", "") }

// jnBestEffort, when truthy (E2E_JN_BEST_EFFORT=1), downgrades a JN bring-up
// failure from fatal to a loud warning so `up` still persists the stack — used to
// validate the open ledger/auditor/tools path while the JN image lags the branch
// (the released ghcr JN predates the open-HTTPS JN→ledger leg). Default off: the
// JN is the write gate, so its failure is fatal in normal operation.
func jnBestEffort() bool {
	switch strings.ToLower(env("E2E_JN_BEST_EFFORT", "")) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
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
		// ledger + auditor carry the open-HTTPS server / open-client postures; the
		// fleet is pinned to the tooling v0.0.4 release (libs/{federation,accounting}
		// hoist + retention invariant). Override per-image via E2E_*_IMAGE.
		Ledger:     env("E2E_LEDGER_IMAGE", tooling+"/ledger:0.0.4"+suffix),
		Witness:    env("E2E_WITNESS_IMAGE", tooling+"/witness:0.0.4"),
		Auditor:    env("E2E_AUDITOR_IMAGE", tooling+"/auditor:0.0.4"),
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
