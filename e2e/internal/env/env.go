// Package env is the harness's bridge from a live e2e run to the addressable
// Config the moved test suites consume.
//
// It resolves the current run via the runstore (the latest id under
// $E2E_RUN_ROOT), reads that run's persisted stack manifest — the per-network
// host ports the provisioner records for exactly this purpose
// (runstore.NetworkManifest) — and derives each network's service URLs plus the
// run's shared TLS material, topology manifest, and per-network bootstrap docs.
//
// Witness endpoints are the one tier the manifest does NOT carry (witnesses are
// not host-published by default), so they come from E2E_<NET>_WITNESS_URLS.
//
// With no provisioned run (a bare `go test`), Load returns a best-effort Config
// and the harness Gates turn every unreachable tier into a clean skip — so the
// suite always constructs.
//
// Defaults derive from the run; every value has an env override so a custom or
// out-of-tree stack can be addressed without a runstore manifest:
//
//	E2E_STRICT, E2E_H1_SEEDED, E2E_FORK_ENABLE                  (bool: 1/true/yes/on)
//	E2E_TOPOLOGY, E2E_CA_CERT, E2E_CLIENT_CERT, E2E_CLIENT_KEY  (path)
//	E2E_<NET>_LEDGER_URL / _JN_URL / _AGGREGATOR_URL            (url)
//	E2E_<NET>_BOOTSTRAP                                         (path)
//	E2E_<NET>_WITNESS_URLS / _AUDITOR_URLS                      (comma-separated)
//	E2E_<NET>_QUORUM_K                                          (int)
//
// where <NET> is FEDERAL, TN, or CA. Ledger and JN are https (CA-pinned / mTLS
// edge); aggregator and auditor use plain clients (http) — matching the typed
// clients in e2e/internal/clients.
package env

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/clearcompass-ai/judicial-network/e2e/runstore"
)

// certFile / bootstrap basenames the provisioner writes under the run layout
// (see e2e/stack: MintCerts → certs/ca.crt|client.crt|client.key; fixtures →
// fixtures/<network>/network-bootstrap.json).
const (
	caCertFile     = "ca.crt"
	clientCertFile = "client.crt"
	clientKeyFile  = "client.key"
	bootstrapFile  = "network-bootstrap.json"
	topologyFile   = "topology.json"
)

// Config is the harness's resolved view of a run: the shared TLS material +
// topology manifest path, the three federation networks, and the prerequisite
// gate flags.
type Config struct {
	TopologyPath string
	CACert       string
	ClientCert   string
	ClientKey    string
	PGContainer  string // shared postgres container for the run (one per stack)

	Strict      bool // a missing dependency is fatal, not a skip
	H1Seeded    bool // varied entry types + delegations seeded (prereq H1)
	ForkEnabled bool // a fork-injection fixture exists (prereq H4)

	Federal NetworkConfig
	TN      NetworkConfig
	CA      NetworkConfig
}

// NetworkConfig is one network's externally-addressable surface.
type NetworkConfig struct {
	Name          string
	LedgerURL     string
	JNURL         string
	AggregatorURL string
	WitnessURLs   []string
	AuditorURLs   []string
	BootstrapPath string
	QuorumK       int
}

// Load resolves the latest run under $E2E_RUN_ROOT and builds the Config from its
// persisted stack manifest, applying E2E_* overrides on top. Any resolution miss
// (no run, no manifest) degrades to a best-effort Config rather than failing.
func Load() Config {
	cfg := Config{
		Strict:      envBool("E2E_STRICT"),
		H1Seeded:    envBool("E2E_H1_SEEDED"),
		ForkEnabled: envBool("E2E_FORK_ENABLE"),
	}

	// Resolve the live run (latest provisioned id); tolerate its absence.
	var (
		lay  *runstore.Layout
		nets []runstore.NetworkManifest
	)
	root := runstore.Root()
	if id, err := runstore.ResolveID("", root, true); err == nil {
		if lay, err = runstore.NewUnder(root, id); err == nil {
			cfg.TopologyPath = filepath.Join(lay.Home, topologyFile)
			cfg.CACert = filepath.Join(lay.Certs, caCertFile)
			cfg.ClientCert = filepath.Join(lay.Certs, clientCertFile)
			cfg.ClientKey = filepath.Join(lay.Certs, clientKeyFile)
			if m, err := lay.LoadManifest(); err == nil {
				nets = m.Networks
			}
			cfg.PGContainer = "baseproof-" + id + "-postgres" // matches stack.Infra.PG()
		}
	}

	cfg.TopologyPath = envOr("E2E_TOPOLOGY", cfg.TopologyPath)
	cfg.CACert = envOr("E2E_CA_CERT", cfg.CACert)
	cfg.ClientCert = envOr("E2E_CLIENT_CERT", cfg.ClientCert)
	cfg.ClientKey = envOr("E2E_CLIENT_KEY", cfg.ClientKey)
	cfg.PGContainer = envOr("E2E_PG_CONTAINER", cfg.PGContainer)

	byName := make(map[string]runstore.NetworkManifest, len(nets))
	for _, n := range nets {
		byName[strings.ToLower(n.Name)] = n
	}
	// A single-network preset carries one network; surface it as Federal so the
	// primary-network gates resolve. TN/CA then stay empty and skip/Pending.
	if _, ok := byName["federal"]; !ok && len(nets) == 1 {
		byName["federal"] = nets[0]
	}

	fixtures := ""
	if lay != nil {
		fixtures = lay.Fixtures
	}
	cfg.Federal = network("FEDERAL", byName["federal"], fixtures)
	cfg.TN = network("TN", byName["tn"], fixtures)
	cfg.CA = network("CA", byName["ca"], fixtures)
	return cfg
}

// network builds one NetworkConfig from a manifest entry (zero-valued when the
// network is absent), then applies the E2E_<NET>_* overrides. envPrefix is the
// uppercase token: FEDERAL, TN, or CA.
func network(envPrefix string, nm runstore.NetworkManifest, fixtures string) NetworkConfig {
	name := nm.Name
	if name == "" {
		name = strings.ToLower(envPrefix)
	}
	nc := NetworkConfig{
		Name:          name,
		LedgerURL:     hostURL("https", nm.LedgerPort),
		JNURL:         hostURL("https", nm.JNPort),
		AggregatorURL: hostURL("http", nm.AggregatorPort),
		QuorumK:       nm.QuorumK,
	}
	for _, p := range nm.AuditorPorts {
		if u := hostURL("http", p); u != "" {
			nc.AuditorURLs = append(nc.AuditorURLs, u)
		}
	}
	if fixtures != "" {
		nc.BootstrapPath = filepath.Join(fixtures, name, bootstrapFile)
	}

	nc.LedgerURL = envOr("E2E_"+envPrefix+"_LEDGER_URL", nc.LedgerURL)
	nc.JNURL = envOr("E2E_"+envPrefix+"_JN_URL", nc.JNURL)
	nc.AggregatorURL = envOr("E2E_"+envPrefix+"_AGGREGATOR_URL", nc.AggregatorURL)
	nc.BootstrapPath = envOr("E2E_"+envPrefix+"_BOOTSTRAP", nc.BootstrapPath)
	if v := os.Getenv("E2E_" + envPrefix + "_WITNESS_URLS"); v != "" {
		nc.WitnessURLs = splitList(v)
	}
	if v := os.Getenv("E2E_" + envPrefix + "_AUDITOR_URLS"); v != "" {
		nc.AuditorURLs = splitList(v)
	}
	if v := os.Getenv("E2E_" + envPrefix + "_QUORUM_K"); v != "" {
		if k, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			nc.QuorumK = k
		}
	}
	return nc
}

// hostURL renders a localhost URL for a published host port (empty when unset).
func hostURL(scheme string, port int) string {
	if port <= 0 {
		return ""
	}
	return fmt.Sprintf("%s://localhost:%d", scheme, port)
}

// splitList parses a comma-separated env value, trimming blanks.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// envOr returns the trimmed env value for key, or def when unset/blank.
func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// envBool reads a truthy env flag (1/true/yes/on, case-insensitive).
func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
