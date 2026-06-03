package stack

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/clearcompass-ai/judicial-network/e2e/dockerx"
)

// ── health helpers ────────────────────────────────────────────────────────

func poll(timeout time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if fn() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Second)
	}
}

func httpStatus(url string) int {
	resp, err := http.Get(url)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func mtlsClient(certsDir string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(certsDir, "client.crt"), filepath.Join(certsDir, "client.key"))
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(certsDir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			ServerName:   "localhost",
		}},
	}, nil
}

// ── host-side mTLS probes (the ledger edge requires a client cert) ─────────

var (
	ledgerClientsMu sync.Mutex
	ledgerClients   = map[string]*http.Client{}
)

// ledgerHTTP returns an mTLS client (cached per certsDir) for HOST→ledger probes
// over the published host port. The ledger edge is mTLS-only, so a plain
// http.Get is refused; the server cert's SAN carries localhost for host access.
func ledgerHTTP(certsDir string) *http.Client {
	ledgerClientsMu.Lock()
	defer ledgerClientsMu.Unlock()
	if c, ok := ledgerClients[certsDir]; ok {
		return c
	}
	c, err := mtlsClient(certsDir)
	if err != nil {
		c = &http.Client{Timeout: 5 * time.Second} // fails closed against the https edge
	}
	ledgerClients[certsDir] = c
	return c
}

// ledgerBody GETs an mTLS ledger URL and returns the trimmed body ("" on error).
func ledgerBody(certsDir, url string) string {
	resp, err := ledgerHTTP(certsDir).Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b))
}

// ── Infra: shared postgres + object store ─────────────────────────────────

// Infra is the stack-wide postgres + seaweedfs (one of each; networks get their
// own databases on the shared postgres).
type Infra struct {
	prefix     string // "baseproof-{id}"
	network    string
	images     Images
	pgMaxConns int
}

func (in Infra) PG() string { return in.prefix + "-postgres" }
func (in Infra) S3() string { return in.prefix + "-seaweedfs" }

// Up brings up postgres (sized to the ledger pool + auditor pools + headroom) and
// seaweedfs, and creates the object-store bucket.
func (in Infra) Up() error {
	pool := in.pgMaxConns
	if pool == 0 {
		pool = 32
	}
	if r := dockerx.Run(dockerx.RunSpec{
		Name: in.PG(), Network: in.network, Image: in.images.Postgres, Detached: true,
		Env: map[string]string{"POSTGRES_USER": pgUser, "POSTGRES_PASSWORD": pgPassword, "POSTGRES_DB": pgDBDefault},
		ImageArgs: []string{
			"-c", "fsync=off", "-c", "synchronous_commit=off",
			"-c", fmt.Sprintf("max_connections=%d", pool+200),
		},
	}); !r.OK() {
		return fmt.Errorf("postgres run: %s", tail(r.Stderr, 300))
	}
	if !poll(120*time.Second, func() bool {
		return dockerx.Exec(in.PG(), []string{"pg_isready", "-U", pgUser, "-d", pgDBDefault}, false).OK()
	}) {
		return fmt.Errorf("postgres never became ready")
	}
	if r := dockerx.Run(dockerx.RunSpec{
		Name: in.S3(), Network: in.network, Image: in.images.Seaweed, Detached: true,
		ImageArgs: []string{"server", "-s3", "-s3.port=8333", "-s3.allowEmptyFolder=true", "-ip.bind=0.0.0.0"},
	}); !r.OK() {
		return fmt.Errorf("seaweedfs run: %s", tail(r.Stderr, 300))
	}
	if !poll(120*time.Second, func() bool {
		return dockerx.Exec(in.S3(), []string{"wget", "-q", "--spider", "http://localhost:9333/cluster/status"}, false).OK()
	}) {
		return fmt.Errorf("seaweedfs never became ready")
	}
	dockerx.Run(dockerx.RunSpec{
		Network: in.network, Image: in.images.Seaweed, Remove: true, Entrypoint: "/bin/sh",
		ImageArgs: []string{"-c", fmt.Sprintf(
			"sleep 2; echo 's3.bucket.create -name %s' | weed shell -master %s:9333", bucket, in.S3())},
	})
	return nil
}

// EnsureDB creates a database if missing and CONFIRMS it exists — race-safe against
// the postgres-image init restart (pg_isready can pass against the temporary init
// server before the real one is up, losing a createdb). Carried over from the
// flake fix that stopped the intermittent "database does not exist" auditor crash.
func (in Infra) EnsureDB(db string) error {
	if !poll(120*time.Second, func() bool {
		dockerx.Exec(in.PG(), []string{"createdb", "-U", pgUser, db}, false) // already-exists / not-ready ignored
		v, ok := dockerx.PGQuery(in.PG(), pgUser, pgDBDefault, "SELECT 1 FROM pg_database WHERE datname='"+db+"'")
		return ok && v == "1"
	}) {
		return fmt.Errorf("database %q never became present", db)
	}
	return nil
}

// ── per-network services ──────────────────────────────────────────────────

func witnessEndpoints(nc NetConfig) string {
	eps := make([]string, nc.Spec.Witnesses)
	for i := 1; i <= nc.Spec.Witnesses; i++ {
		eps[i-1] = "http://" + nc.Name(fmt.Sprintf("witness-%d", i)) + ":8081"
	}
	return strings.Join(eps, ",")
}

// UpWitnessFleet brings up this network's witnesses (no host-port publish — the
// ledger reaches them over the docker network; readiness is read from each
// witness's own startup log).
func UpWitnessFleet(nc NetConfig, fixturesDir, witnessImage string) error {
	for i := 1; i <= nc.Spec.Witnesses; i++ {
		name := nc.Name(fmt.Sprintf("witness-%d", i))
		if r := dockerx.Run(dockerx.RunSpec{
			Name: name, Network: nc.Network, Image: witnessImage, Detached: true, User: uidGID(),
			Mounts: []dockerx.Mount{{Host: fixturesDir, Container: mntKeys + ":ro"}},
			ImageArgs: []string{
				"-addr=:8081",
				fmt.Sprintf("-key-file=%s/witnesses/witness-%d.pem", mntKeys, i),
				"-bootstrap=" + mntKeys + "/network-bootstrap.json",
			},
		}); !r.OK() {
			return fmt.Errorf("%s run: %s", name, tail(r.Stderr, 300))
		}
		if !poll(60*time.Second, func() bool {
			return dockerx.LogCount(name, "standalone-witness ready") > 0
		}) {
			return fmt.Errorf("%s never logged ready", name)
		}
	}
	return nil
}

// ledgerBaseEnv is the deterministic ledger env; UpLedger layers the conditional
// tuning/signer knobs on top. The ledger terminates mTLS in-binary
// (LEDGER_INBOUND_CLIENT_CA_FILE is mandatory the moment LEDGER_TLS_CERT_FILE is
// set), so the edge is mTLS-only: every caller — the auditors, the JN, the
// aggregator, the seed/backfill/audit tool containers, and the host probes —
// presents the shared client cert.
func ledgerBaseEnv(nc NetConfig, in Infra) map[string]string {
	return map[string]string{
		"LEDGER_DATABASE_URL":             dsn(in.PG(), nc.DB),
		"LEDGER_LOG_DID":                  nc.LogDID,
		"LEDGER_ADDR":                     ":8080",
		"LEDGER_BYTE_STORE_BACKEND":       "s3",
		"LEDGER_BYTE_STORE_S3_ENDPOINT":   "http://" + in.S3() + ":8333",
		"LEDGER_BYTE_STORE_S3_BUCKET":     bucket,
		"LEDGER_BYTE_STORE_S3_REGION":     "us-east-1",
		"LEDGER_BYTE_STORE_S3_ACCESS_KEY": "any",
		"LEDGER_BYTE_STORE_S3_SECRET_KEY": "any",
		"LEDGER_BYTE_STORE_S3_PATH_STYLE": "true",
		"LEDGER_WITNESS_ENDPOINTS":        witnessEndpoints(nc),
		"LEDGER_WITNESS_QUORUM_K":         strconv.Itoa(nc.Spec.QuorumK),
		"LEDGER_NETWORK_BOOTSTRAP_FILE":   mntFixtures + "/network-bootstrap.json",
		"LEDGER_TESSERA_STORAGE_DIR":      "/var/lib/ledger/tessera",
		"LEDGER_WAL_PATH":                 "/var/lib/ledger/wal",
		"LEDGER_TESSERA_ANTISPAM_PATH":    "/var/lib/ledger/antispam",
		"LEDGER_SMT_TILE_EMIT_DIR":        tileDir,
		"LEDGER_SMT_PROOF_SOURCE":         nc.Tuning.ProofSource,
		"LEDGER_SEQUENCER_INTERVAL":       sequencerInterval(),
		// mTLS edge — the ledger terminates TLS in-binary and REQUIRES a client
		// cert from every caller (server cert SAN covers this container's name).
		"LEDGER_TLS_CERT_FILE":          mntCerts + "/server.crt",
		"LEDGER_TLS_KEY_FILE":           mntCerts + "/server.key",
		"LEDGER_INBOUND_CLIENT_CA_FILE": mntCerts + "/ca.crt",
	}
}

// UpLedger brings up this network's ledger (S3-backed, witness-cosigned, mTLS
// edge) and gates on its mTLS /healthz.
func UpLedger(nc NetConfig, in Infra, fixturesDir, certsDir, ledgerImage string) error {
	envm := ledgerBaseEnv(nc, in)
	if nc.Tuning.SequencerMaxInflight > 0 {
		envm["LEDGER_SEQUENCER_MAX_INFLIGHT"] = strconv.Itoa(nc.Tuning.SequencerMaxInflight)
	}
	if nc.Tuning.PGMaxConns > 0 {
		envm["LEDGER_PG_MAX_CONNS"] = strconv.Itoa(nc.Tuning.PGMaxConns)
	}
	if lvl := ledgerLogLevel(); lvl != "" {
		envm["LEDGER_LOG_LEVEL"] = lvl
	}
	if _, err := os.Stat(filepath.Join(fixturesDir, "ledger-signer.key")); err == nil {
		envm["LEDGER_SIGNER_KEY_FILE"] = mntFixtures + "/ledger-signer.key"
	}
	if r := dockerx.Run(dockerx.RunSpec{
		Name: nc.Name("ledger"), Network: nc.Network, Image: ledgerImage, Detached: true,
		Env:   envm,
		Ports: []dockerx.Port{{Host: nc.LedgerPort, Container: 8080}},
		Mounts: []dockerx.Mount{
			{Host: fixturesDir, Container: mntFixtures + ":ro"},
			{Host: certsDir, Container: mntCerts + ":ro"},
		},
	}); !r.OK() {
		return fmt.Errorf("%s run: %s", nc.Name("ledger"), tail(r.Stderr, 300))
	}
	if !poll(120*time.Second, func() bool {
		return ledgerBody(certsDir, fmt.Sprintf("https://localhost:%d/healthz", nc.LedgerPort)) == "ok"
	}) {
		return fmt.Errorf("%s mTLS /healthz never == ok", nc.Name("ledger"))
	}
	return nil
}

// auditorEnv is one auditor's deterministic env. Its OWN listener stays plain
// http (probed over the host port), but it pulls from the ledger over the mTLS
// edge — AUDITOR_PEERS is the https ledger URL and AUDITOR_PEER_* present the
// shared client cert.
func auditorEnv(nc NetConfig, in Infra, idx int) map[string]string {
	return map[string]string{
		"AUDITOR_LISTEN_ADDR":            ":8088",
		"AUDITOR_GOSSIP_DSN":             dsn(in.PG(), nc.GossipDB(idx)),
		"AUDITOR_NETWORK_BOOTSTRAP_FILE": mntFixtures + "/network-bootstrap.json",
		"AUDITOR_WITNESS_QUORUM_K":       strconv.Itoa(nc.Spec.QuorumK),
		"AUDITOR_ORIGINATOR_DISCOVERY":   "true",
		"AUDITOR_PEERS":                  nc.LogDID + "=https://" + nc.Name("ledger") + ":8080",
		"AUDITOR_PEER_CLIENT_CERT_FILE":  mntCerts + "/client.crt",
		"AUDITOR_PEER_CLIENT_KEY_FILE":   mntCerts + "/client.key",
		"AUDITOR_PEER_CA_FILE":           mntCerts + "/ca.crt",
		"AUDITOR_POLL_INTERVAL":          auditorPollInterval(),
		"AUDITOR_HORIZON_INTERVAL":       auditorHorizonInterval(),
		"AUDITOR_HORIZON_SAMPLES":        auditHorizonSamples(),
	}
}

// UpAuditors brings up this network's auditors. Their gossip databases must already
// exist (the builder EnsureDB's them first). Each auditor pulls from the ledger
// over the mTLS edge; its own probe listener stays plain http.
func UpAuditors(nc NetConfig, in Infra, fixturesDir, certsDir, auditorImage string) error {
	for idx := 1; idx <= nc.Spec.Auditors; idx++ {
		port := nc.AuditorPorts[idx-1]
		name := nc.Name(fmt.Sprintf("auditor-%d", idx))
		if r := dockerx.Run(dockerx.RunSpec{
			Name: name, Network: nc.Network, Image: auditorImage, Detached: true,
			Env:   auditorEnv(nc, in, idx),
			Ports: []dockerx.Port{{Host: port, Container: 8088}},
			Mounts: []dockerx.Mount{
				{Host: fixturesDir, Container: mntFixtures + ":ro"},
				{Host: certsDir, Container: mntCerts + ":ro"},
			},
		}); !r.OK() {
			return fmt.Errorf("%s run: %s", name, tail(r.Stderr, 300))
		}
		if !poll(120*time.Second, func() bool {
			return httpStatus(fmt.Sprintf("http://localhost:%d/readyz", port)) == 200
		}) {
			return fmt.Errorf("%s /readyz never == 200", name)
		}
	}
	return nil
}

// jnEnv is the JN enforcer's deterministic env. Its own listener is mTLS
// (API_AUTH_*); it reaches the ledger over the mTLS edge (API_LEDGER_ENDPOINT
// https + API_LEDGER_* client cert); the gossip-ingest peer is the auditor's
// plain-http feed, not the ledger, so it stays http.
func jnEnv(nc NetConfig) map[string]string {
	return map[string]string{
		"API_LISTEN_ADDR":            ":8443",
		"API_LEDGER_ENDPOINT":        "https://" + nc.Name("ledger") + ":8080",
		"API_LEDGER_CERT_FILE":       mntCerts + "/client.crt",
		"API_LEDGER_KEY_FILE":        mntCerts + "/client.key",
		"API_LEDGER_CA_FILE":         mntCerts + "/ca.crt",
		"API_NETWORK_BOOTSTRAP_FILE": mntFixtures + "/network-bootstrap.json",
		"API_WITNESS_QUORUM_K":       strconv.Itoa(nc.Spec.QuorumK),
		"API_GOSSIP_INGEST_ENABLED":  "true",
		"API_GOSSIP_INGEST_PEER_URL": "http://" + nc.Name("auditor-1") + ":8088",
		"API_AUTH_CLIENT_CA_FILE":    mntCerts + "/ca.crt",
		"API_AUTH_TLS_CERT_FILE":     mntCerts + "/server.crt",
		"API_AUTH_TLS_KEY_FILE":      mntCerts + "/server.key",
	}
}

// UpJN brings up this network's JN enforcer (mTLS, verify-only ingest from
// auditor-1) and gates on its mTLS /readyz.
func UpJN(nc NetConfig, certsDir, fixturesDir, jnImage string) error {
	if r := dockerx.Run(dockerx.RunSpec{
		Name: nc.Name("jn"), Network: nc.Network, Image: jnImage, Detached: true,
		Env:   jnEnv(nc),
		Ports: []dockerx.Port{{Host: nc.JNPort, Container: 8443}},
		Mounts: []dockerx.Mount{
			{Host: fixturesDir, Container: mntFixtures + ":ro"},
			{Host: certsDir, Container: mntCerts + ":ro"},
		},
	}); !r.OK() {
		return fmt.Errorf("%s run: %s", nc.Name("jn"), tail(r.Stderr, 300))
	}
	client, err := mtlsClient(certsDir)
	if err != nil {
		return fmt.Errorf("jn mTLS client: %w", err)
	}
	if !poll(120*time.Second, func() bool {
		resp, err := client.Get(fmt.Sprintf("https://localhost:%d/readyz", nc.JNPort))
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == 200
	}) {
		return fmt.Errorf("%s mTLS /readyz never == 200", nc.Name("jn"))
	}
	return nil
}

// aggregatorEnv is the read-projection aggregator's deterministic env. It scans
// the ledger over the mTLS edge (TOOLS_LEDGER_URL https + TOOLS_LEDGER_*_FILE
// client cert — the ledger mandates mTLS) and indexes into its OWN projection DB;
// the three log DIDs all point at the network's bootstrap log.
func aggregatorEnv(nc NetConfig, in Infra) map[string]string {
	return map[string]string{
		"TOOLS_DATABASE_URL":            dsn(in.PG(), nc.AggDB),
		"TOOLS_LEDGER_URL":              "https://" + nc.Name("ledger") + ":8080",
		"TOOLS_LEDGER_CLIENT_CERT_FILE": mntCerts + "/client.crt",
		"TOOLS_LEDGER_CLIENT_KEY_FILE":  mntCerts + "/client.key",
		"TOOLS_LEDGER_CA_FILE":          mntCerts + "/ca.crt",
		"TOOLS_OFFICERS_LOG":            nc.LogDID,
		"TOOLS_CASES_LOG":               nc.LogDID,
		"TOOLS_PARTIES_LOG":             nc.LogDID,
	}
}

// UpAggregator brings up this network's read-projection aggregator (mTLS outbound
// to the ledger edge; plain-http probe surface, so /healthz + /readyz are probed
// over plain http). Its projection DB must already exist (the builder EnsureDB's
// it first). /readyz is db+ledger-gated.
func UpAggregator(nc NetConfig, in Infra, certsDir, aggregatorImage string) error {
	if r := dockerx.Run(dockerx.RunSpec{
		Name: nc.Name("aggregator"), Network: nc.Network, Image: aggregatorImage, Detached: true,
		Env:    aggregatorEnv(nc, in),
		Ports:  []dockerx.Port{{Host: nc.AggregatorPort, Container: 8092}},
		Mounts: []dockerx.Mount{{Host: certsDir, Container: mntCerts + ":ro"}},
	}); !r.OK() {
		return fmt.Errorf("%s run: %s", nc.Name("aggregator"), tail(r.Stderr, 300))
	}
	if !poll(120*time.Second, func() bool {
		return httpStatus(fmt.Sprintf("http://localhost:%d/healthz", nc.AggregatorPort)) == 200
	}) {
		return fmt.Errorf("%s /healthz never == 200", nc.Name("aggregator"))
	}
	if !poll(120*time.Second, func() bool {
		return httpStatus(fmt.Sprintf("http://localhost:%d/readyz", nc.AggregatorPort)) == 200
	}) {
		return fmt.Errorf("%s /readyz never == 200 (db + ledger gated)", nc.Name("aggregator"))
	}
	return nil
}

// AggregatorReady probes the aggregator's plain-http /healthz then /readyz over
// its published host port. /readyz is 200 only when BOTH the projection DB and
// the (mTLS) ledger edge are reachable (the aggregator's probes.go), so a true
// result proves the read-projection's scan-pipeline wiring end-to-end.
func AggregatorReady(port int) bool {
	return httpStatus(fmt.Sprintf("http://localhost:%d/healthz", port)) == 200 &&
		httpStatus(fmt.Sprintf("http://localhost:%d/readyz", port)) == 200
}
