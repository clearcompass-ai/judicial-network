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

func httpBody(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b))
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

// UpLedger brings up this network's ledger (S3-backed, witness-cosigned) and gates
// on /healthz.
func UpLedger(nc NetConfig, in Infra, fixturesDir, ledgerImage string) error {
	envm := map[string]string{
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
	}
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
		Env:    envm,
		Ports:  []dockerx.Port{{Host: nc.LedgerPort, Container: 8080}},
		Mounts: []dockerx.Mount{{Host: fixturesDir, Container: mntFixtures + ":ro"}},
	}); !r.OK() {
		return fmt.Errorf("%s run: %s", nc.Name("ledger"), tail(r.Stderr, 300))
	}
	if !poll(120*time.Second, func() bool {
		return httpBody(fmt.Sprintf("http://localhost:%d/healthz", nc.LedgerPort)) == "ok"
	}) {
		return fmt.Errorf("%s /healthz never == ok", nc.Name("ledger"))
	}
	return nil
}

// UpAuditors brings up this network's auditors. Their gossip databases must already
// exist (the builder EnsureDB's them first).
func UpAuditors(nc NetConfig, in Infra, fixturesDir, auditorImage string) error {
	for idx := 1; idx <= nc.Spec.Auditors; idx++ {
		port := nc.AuditorPorts[idx-1]
		name := nc.Name(fmt.Sprintf("auditor-%d", idx))
		envm := map[string]string{
			"AUDITOR_LISTEN_ADDR":            ":8088",
			"AUDITOR_GOSSIP_DSN":             dsn(in.PG(), nc.GossipDB(idx)),
			"AUDITOR_NETWORK_BOOTSTRAP_FILE": mntFixtures + "/network-bootstrap.json",
			"AUDITOR_WITNESS_QUORUM_K":       strconv.Itoa(nc.Spec.QuorumK),
			"AUDITOR_ORIGINATOR_DISCOVERY":   "true",
			"AUDITOR_PEERS":                  nc.LogDID + "=http://" + nc.Name("ledger") + ":8080",
			"AUDITOR_POLL_INTERVAL":          auditorPollInterval(),
			"AUDITOR_HORIZON_INTERVAL":       auditorHorizonInterval(),
			"AUDITOR_HORIZON_SAMPLES":        auditHorizonSamples(),
		}
		if r := dockerx.Run(dockerx.RunSpec{
			Name: name, Network: nc.Network, Image: auditorImage, Detached: true,
			Env:    envm,
			Ports:  []dockerx.Port{{Host: port, Container: 8088}},
			Mounts: []dockerx.Mount{{Host: fixturesDir, Container: mntFixtures + ":ro"}},
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

// UpJN brings up this network's JN enforcer (mTLS, verify-only ingest from
// auditor-1) and gates on its mTLS /readyz.
func UpJN(nc NetConfig, certsDir, fixturesDir, jnImage string) error {
	envm := map[string]string{
		"API_LISTEN_ADDR":            ":8443",
		"API_LEDGER_ENDPOINT":        "http://" + nc.Name("ledger") + ":8080",
		"API_NETWORK_BOOTSTRAP_FILE": mntFixtures + "/network-bootstrap.json",
		"API_WITNESS_QUORUM_K":       strconv.Itoa(nc.Spec.QuorumK),
		"API_GOSSIP_INGEST_ENABLED":  "true",
		"API_GOSSIP_INGEST_PEER_URL": "http://" + nc.Name("auditor-1") + ":8088",
		"API_AUTH_CLIENT_CA_FILE":    mntCerts + "/ca.crt",
		"API_AUTH_TLS_CERT_FILE":     mntCerts + "/server.crt",
		"API_AUTH_TLS_KEY_FILE":      mntCerts + "/server.key",
	}
	if r := dockerx.Run(dockerx.RunSpec{
		Name: nc.Name("jn"), Network: nc.Network, Image: jnImage, Detached: true,
		Env:   envm,
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
