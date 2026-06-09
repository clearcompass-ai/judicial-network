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

// ── host-side open-HTTPS probes (verify the ledger's server cert, no client cert) ──

var (
	ledgerClientsMu sync.Mutex
	ledgerClients   = map[string]*http.Client{}
)

// ledgerHTTP returns a server-verify client (cached per certsDir) for HOST→ledger
// probes over the published host port. The ledger serves OPEN HTTPS — reads are
// open, writes gated by in-body crypto — so the probe presents NO client cert and
// only pins the run CA to verify the ledger's server cert (SAN carries localhost
// for host access). That a certless caller reads at all IS the open-HTTPS proof.
func ledgerHTTP(certsDir string) *http.Client {
	ledgerClientsMu.Lock()
	defer ledgerClientsMu.Unlock()
	if c, ok := ledgerClients[certsDir]; ok {
		return c
	}
	c, err := serverTrustClient(certsDir) // open HTTPS: verify the ledger's server cert, present NO client cert
	if err != nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	ledgerClients[certsDir] = c
	return c
}

// ledgerBody GETs an open-HTTPS ledger URL (server-verify, no client cert) and
// returns the trimmed body ("" on error).
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
		// Publish the S3 port to the host so an OFF-NETWORK verifier (the host-side
		// e2e runner) can follow the ledger's 302 redirect for SHIPPED entries and
		// fetch the bytes — the same way a production verifier reaches the public
		// bytestore CDN. seaweedfs runs with no configured identities, so the GET is
		// anonymous (no S3 signing). See ledgerBaseEnv's PUBLIC_BASE_URL.
		Ports:     []dockerx.Port{{Host: seaweedHostPort(), Container: 8333}},
		ImageArgs: []string{"server", "-s3", "-s3.port=8333", "-s3.allowEmptyFolder=true", "-ip.bind=0.0.0.0"},
	}); !r.OK() {
		return fmt.Errorf("seaweedfs run: %s", tail(r.Stderr, 300))
	}
	if !poll(120*time.Second, func() bool {
		return dockerx.Exec(in.S3(), []string{"wget", "-q", "--spider", "http://localhost:9333/cluster/status"}, false).OK()
	}) {
		return fmt.Errorf("seaweedfs never became ready")
	}
	// Buckets are created PER NETWORK (Build → CreateBucket before each ledger), so
	// the ledger's fixed-name objects (the cosigned-checkpoint horizon) live in an
	// isolated namespace per log and can never be clobbered by another network's
	// writer. No shared bucket is created here.
	return nil
}

// CreateBucket creates an object-store bucket on the shared seaweedfs (idempotent;
// best-effort, mirroring the original inline creation). Each network gets its OWN
// bucket so the fixed-name cosigned-checkpoint object — and any other
// non-content-addressed key — can never overlap across logs.
func (in Infra) CreateBucket(name string) {
	dockerx.Run(dockerx.RunSpec{
		Network: in.network, Image: in.images.Seaweed, Remove: true, Entrypoint: "/bin/sh",
		ImageArgs: []string{"-c", fmt.Sprintf(
			"sleep 2; echo 's3.bucket.create -name %s' | weed shell -master %s:9333", name, in.S3())},
	})
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
// tuning/signer knobs on top. The ledger serves OPEN HTTPS: it terminates TLS
// in-binary (server cert/key) but does NOT set LEDGER_INBOUND_CLIENT_CA_FILE, so
// the listener is tls.NoClientCert — reads are open to any caller and writes are
// gated by in-body crypto (admission + the G5 WriteAuthorization signature), not
// transport identity. Every caller — auditors, JN, aggregator, the
// seed/backfill/audit tool containers, the host probes — verifies the server cert
// against the run CA and presents NO client cert.
// seaweedHostPort is the host port the shared seaweedfs S3 endpoint is published
// on, so host-side verifiers can follow shipped-entry redirects. Override with
// E2E_SEAWEED_HOST_PORT to avoid a clash when running multiple stacks. Default 8333.
func seaweedHostPort() int {
	if v := os.Getenv("E2E_SEAWEED_HOST_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 8333
}

func ledgerBaseEnv(nc NetConfig, in Infra) map[string]string {
	return map[string]string{
		"LEDGER_DATABASE_URL":           dsn(in.PG(), nc.DB),
		"LEDGER_LOG_DID":                nc.LogDID,
		"LEDGER_ADDR":                   ":8080",
		"LEDGER_BYTE_STORE_BACKEND":     "s3",
		"LEDGER_BYTE_STORE_S3_ENDPOINT": "http://" + in.S3() + ":8333",
		// Public URL the ledger puts in the 302 Location for SHIPPED entries.
		// Host-reachable (seaweedfs is published to the host) so the host-side
		// proof/verify recipes can follow the redirect and fetch the bytes — the
		// e2e analog of a production public bytestore. The ledger itself reads/writes
		// via the in-network S3_ENDPOINT above; this only addresses external readers.
		//
		// MUST include the bucket: PublicURL = base + "/" + key(seq,hash), and the
		// empty-default is DefaultS3PathStyle(endpoint, bucket) which embeds the
		// bucket. Omitting it yields ".../entries/<seq>/<hash>" (no bucket) → 404.
		"LEDGER_BYTE_STORE_PUBLIC_BASE_URL": fmt.Sprintf("http://localhost:%d/%s", seaweedHostPort(), nc.Bucket),
		"LEDGER_BYTE_STORE_S3_BUCKET":       nc.Bucket,
		"LEDGER_BYTE_STORE_S3_REGION":       "us-east-1",
		"LEDGER_BYTE_STORE_S3_ACCESS_KEY":   "any",
		"LEDGER_BYTE_STORE_S3_SECRET_KEY":   "any",
		"LEDGER_BYTE_STORE_S3_PATH_STYLE":   "true",
		"LEDGER_WITNESS_ENDPOINTS":          witnessEndpoints(nc),
		"LEDGER_WITNESS_QUORUM_K":           strconv.Itoa(nc.Spec.QuorumK),
		"LEDGER_NETWORK_BOOTSTRAP_FILE":     mntFixtures + "/network-bootstrap.json",
		// All under /var/lib/baseproof — the image-owned (uid 65532) parent the
		// non-root ledger can create subdirs in; /var/lib/ledger would be root-owned
		// and uncreatable by the non-root writer (see tileDir in config.go).
		"LEDGER_TESSERA_STORAGE_DIR":   "/var/lib/baseproof/tessera",
		"LEDGER_WAL_PATH":              "/var/lib/baseproof/wal",
		"LEDGER_TESSERA_ANTISPAM_PATH": "/var/lib/baseproof/tessera-antispam",
		"LEDGER_SMT_TILE_EMIT_DIR":     tileDir,
		"LEDGER_SMT_PROOF_SOURCE":      nc.Tuning.ProofSource,
		"LEDGER_SEQUENCER_INTERVAL":    sequencerInterval(),
		// Open HTTPS — the ledger terminates TLS in-binary (server cert SAN covers
		// this container's name) but sets NO inbound client-CA, so the listener does
		// not request a client cert. Reads open; writes gated by in-body crypto.
		"LEDGER_TLS_CERT_FILE": mntCerts + "/server.crt",
		"LEDGER_TLS_KEY_FILE":  mntCerts + "/server.key",
	}
}

// UpLedger brings up this network's ledger (S3-backed, witness-cosigned, open
// HTTPS) and gates on its /healthz over a server-verify (no client cert) probe.
func UpLedger(nc NetConfig, in Infra, fixturesDir, certsDir, ledgerImage string) error {
	envm := ledgerBaseEnv(nc, in)
	if nc.Tuning.SequencerMaxInflight > 0 {
		envm["LEDGER_SEQUENCER_MAX_INFLIGHT"] = strconv.Itoa(nc.Tuning.SequencerMaxInflight)
	}
	if nc.Tuning.PGMaxConns > 0 {
		envm["LEDGER_PG_MAX_CONNS"] = strconv.Itoa(nc.Tuning.PGMaxConns)
	}
	if nc.Tuning.WALRetentionBuffer > 0 {
		envm["LEDGER_WAL_RETENTION_BUFFER"] = strconv.FormatUint(nc.Tuning.WALRetentionBuffer, 10)
		// Short GC poll so verify.walgc observes a reclaim promptly after load —
		// the work-driven GC fires within one poll once a buffer's worth ships.
		envm["LEDGER_WAL_RETENTION_INTERVAL"] = "10s"
	}
	if lvl := ledgerLogLevel(); lvl != "" {
		envm["LEDGER_LOG_LEVEL"] = lvl
	}
	// Opt-in Go pprof listener (heap/alloc/CPU) for memory forensics on the real
	// ledger binary: set E2E_LEDGER_PPROF_ADDR=:6060, then
	//   docker exec <fed-ledger> wget -qO- http://localhost:6060/debug/pprof/heap
	// No host port is published — reach it via `docker exec` inside the container.
	if a := env("E2E_LEDGER_PPROF_ADDR", ""); a != "" {
		envm["LEDGER_PPROF_ADDR"] = a
	}
	// Opt-in tail-GC safety audit (non-destructive): E2E_LEDGER_TAIL_GC_AUDIT=1 runs
	// TailGCAudit each checkpoint and logs any violation at ERROR. Validates the
	// orphan-prune's assumption (published ⇒ durable) in a real soak BEFORE that
	// prune ships. Needs the 0.0.37+ ledger image.
	if v := env("E2E_LEDGER_TAIL_GC_AUDIT", ""); v != "" {
		envm["LEDGER_TAIL_GC_AUDIT"] = v
	}
	// Tail orphan prune (0.0.38+): E2E_LEDGER_TAIL_GC_PRUNE=1 bounds the in-memory
	// SMT node tail to the un-tiled gap (memory flat in history). Keep the audit on
	// alongside as a live safety net (it must read 0 violations).
	if v := env("E2E_LEDGER_TAIL_GC_PRUNE", ""); v != "" {
		envm["LEDGER_TAIL_GC_PRUNE"] = v
	}
	// Leaf-loss fix (v0.1.4). The durable node→tile-top index makes every emitted
	// node resolvable by hash, so a compressed top-skip to a band interior no longer
	// faults "missing node (referenced by ancestor)" → silent PathD → a missing
	// smt_leaves row served as non-membership. It is DEFAULT-ON in the ledger; this
	// passthrough exists so a soak can A/B it (E2E_LEDGER_NODE_INDEX=0 reverts to the
	// top-only resolution that loses leaves, with the builder's MissingNodeError halt
	// catching the gap loudly instead of dropping it).
	if v := env("E2E_LEDGER_NODE_INDEX", ""); v != "" {
		envm["LEDGER_NODE_INDEX"] = v
	}
	// Leaf-loss VALIDATION diagnostics (v0.1.4+), flipped per run with no rebuild —
	// the published fleet carries them all. `up … --trace` presets the first two:
	//   - LEDGER_TRACE_COMMIT=1: a per-batch commit-integrity check that names the
	//     leaf-loss SOURCE node + seq at commit time, O(delta) — a clean soak
	//     pass/fail (0 flags ⇒ the fix holds), before any cascade.
	//   - LEDGER_TILE_VERIFY_FETCH=1: classifies a Get miss (ClassifyTileMiss) as
	//     INTERIOR_TOP_SKIP (the index fixes) vs STRANDED_TOP (a separate bug), so a
	//     residual miss is attributable.
	//   - LEDGER_COMMIT_ALL_NODES=1: commits the FULL overlay delta instead of the
	//     ReachableMutations projection — the isolation toggle for a residual loss.
	//   - LEDGER_TRACE_EVICTION=1: non-destructive eviction shadow on the tailed
	//     node store (tracks would-be-evicted suspects instead of dropping them).
	for _, k := range []string{
		"LEDGER_TRACE_COMMIT", "LEDGER_TILE_VERIFY_FETCH",
		"LEDGER_COMMIT_ALL_NODES", "LEDGER_TRACE_EVICTION",
	} {
		if v := env("E2E_"+k, ""); v != "" {
			envm[k] = v
		}
	}
	// SDK + reconciler Trace Mode (off by default — it is the firehose, distinct
	// from the bounded diagnostics above). BASEPROOF_TRACE=1 lights up
	// builder.ProcessBatch, smt.GetLeaf/SetLeaves/TiledNodeStore, jellyfishInsert's
	// missing-node fault, and the rebuild/WAL/gossip reconcilers — all greppable by
	// the bptrace: prefix. Honored by the published 0.1.4+ fleet (which embeds
	// baseproof v0.0.4-rc2); no custom-built image is needed.
	if v := env("BASEPROOF_TRACE", ""); v != "" {
		envm["BASEPROOF_TRACE"] = v
	}
	// GOMEMLIMIT caps the ledger's Go heap so the runtime GCs/scavenges instead of
	// ratcheting RSS to the high-water (the profile shows the LIVE heap is bounded —
	// Badger memtables + the 4096-tile SMT cache — so the climbing cgroup RSS is just
	// uncollected headroom). Default 1GiB; E2E_LEDGER_GOMEMLIMIT=off disables.
	if v := env("E2E_LEDGER_GOMEMLIMIT", "1GiB"); v != "off" {
		envm["GOMEMLIMIT"] = v
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
		return fmt.Errorf("%s open-HTTPS /healthz never == ok", nc.Name("ledger"))
	}
	return nil
}

// UpReader brings up this network's PG-OFF read front — the SAME ledger image's
// /ledger-reader entrypoint, the SAME shared object store (SeaweedFS) and server
// cert as the writer, but Postgres pointed at a dead host. It reconstructs the
// horizon / inclusion / SMT / receipt proof surface from the object store the
// writer ships its tessera tiles to (tooling 0.0.31+), so it needs no LOG-DATA
// filesystem shared with the writer — only the bucket. The reader serves open HTTPS
// (same cert, gated on /healthz over a server-verify probe), so the proof tooling
// pins it against the run CA exactly as it does the writer. Reuses ledgerBaseEnv
// wholesale: the byte-store/TLS/LogDID env is identical; only the DSN differs. The
// fixtures dir is mounted read-only for ONE genesis CONFIG file the reader serves —
// network-bootstrap.json (GET /v1/network/bootstrap, which the v2 proof gather
// SHA-256-checks against the trust root); the other writer-only env (witnesses,
// sequencer, signer) is harmlessly ignored.
func UpReader(nc NetConfig, in Infra, fixturesDir, certsDir, ledgerImage string) error {
	envm := ledgerBaseEnv(nc, in)
	// Postgres OFF: a well-formed but unresolvable DSN (.invalid never resolves,
	// RFC 2606). The reader boots (LazyConnect) and serves the object-store surface;
	// PG-backed value lookups error per-request — exactly the cold-read contract.
	envm["LEDGER_DATABASE_URL"] = dsn("ledger-reader-pg-off.invalid", nc.DB)
	if lvl := ledgerLogLevel(); lvl != "" {
		envm["LEDGER_LOG_LEVEL"] = lvl
	}
	if r := dockerx.Run(dockerx.RunSpec{
		Name: nc.Name("reader"), Network: nc.Network, Image: ledgerImage, Detached: true,
		Entrypoint: "/ledger-reader",
		Env:        envm,
		// The reader listens on the writer's in-container :8080 (distinct container,
		// so no clash) and is published to its own host port.
		Ports: []dockerx.Port{{Host: nc.ReaderPort, Container: 8080}},
		Mounts: []dockerx.Mount{
			{Host: certsDir, Container: mntCerts + ":ro"},
			{Host: fixturesDir, Container: mntFixtures + ":ro"}, // genesis bootstrap → /v1/network/bootstrap
		},
	}); !r.OK() {
		return fmt.Errorf("%s run: %s", nc.Name("reader"), tail(r.Stderr, 300))
	}
	if !poll(120*time.Second, func() bool {
		return ledgerBody(certsDir, fmt.Sprintf("https://localhost:%d/healthz", nc.ReaderPort)) == "ok"
	}) {
		return fmt.Errorf("%s read front /healthz never == ok", nc.Name("reader"))
	}
	return nil
}

// ── federation.dr — disaster-recovery primitives ──────────────────────────

// pgContainer / s3Container derive the shared-infra container names from a
// network's docker network ("baseproof-{runID}"), which the Infra prefix equals —
// so a recipe with only a Target can reach them.
func pgContainer(network string) string { return network + "-postgres" }
func s3Container(network string) string { return network + "-seaweedfs" }

// WipeLedgerProjection simulates the loss federation.dr recovers from: it removes
// the writer ledger (whose tessera dir is container-internal, so this is a node
// loss; it also closes the ledger's Postgres connections so the projection is
// mutable), then empties the projection tables — mirroring rebuild-projection's
// resetProjectionTables (DELETE entry_index + smt_leaves; reset builder_cursor to
// the -1 sentinel and smt_root_state to a placeholder root). The rebuild then
// reconstructs them from the object store, so a correct post-rebuild state proves
// the reconstruction (not stale leftovers).
func WipeLedgerProjection(t Target) error {
	dockerx.Remove(t.LedgerName)
	pg := pgContainer(t.Network)
	for _, sql := range []string{
		"DELETE FROM entry_index",
		"DELETE FROM smt_leaves",
		"UPDATE builder_cursor SET last_processed_sequence = -1 WHERE id = 1",
		"UPDATE smt_root_state SET current_root = decode('" + strings.Repeat("00", 32) + "', 'hex'), committed_through_seq = 0 WHERE id = 1",
	} {
		if _, ok := dockerx.PGQuery(pg, pgUser, t.DB, sql); !ok {
			return fmt.Errorf("wipe projection: %q failed against %s/%s", sql, pg, t.DB)
		}
	}
	return nil
}

// UpRebuildJob runs /rebuild-projection ONCE against this network, reconstructing
// the Postgres projection (entry_index + SMT) from the OBJECT STORE alone:
// --tiles-from-bytestore reads tessera tiles + entry bytes from the shared store
// (the same bucket/prefix the writer ships to) and takes the head from the
// cosigned horizon. The DR backbone (tooling v0.0.29+). Foreground + --rm; the
// captured Result carries the rebuild's stdout/exit.
func UpRebuildJob(t Target, ledgerImage string) (dockerx.Result, error) {
	name := t.LedgerName + "-rebuild"
	dockerx.Remove(name)
	r := dockerx.Run(dockerx.RunSpec{
		Name: name, Network: t.Network, Image: ledgerImage, Remove: true,
		Entrypoint: "/rebuild-projection",
		ImageArgs: []string{
			"--tiles-from-bytestore",
			"--pg-dsn", dsn(pgContainer(t.Network), t.DB),
			"--log-did", t.LogDID,
			"--bytestore-backend", "s3",
			"--bytestore-bucket", t.Bucket,
			"--bytestore-prefix", "entries", // matches the bytestore default the writer uses
			"--bytestore-endpoint", "http://" + s3Container(t.Network) + ":8333",
			"--bytestore-region", "us-east-1",
			"--bytestore-access-key", "any",
			"--bytestore-secret-key", "any",
			"--bytestore-path-style",
			"--verbose",
		},
	})
	if !r.OK() {
		return r, fmt.Errorf("%s: rebuild-projection failed: %s", name, tail(r.Stderr, 600))
	}
	return r, nil
}

// RebuiltProjectionState reads the post-rebuild projection: the entry_index row
// count and the smt_root_state root (lowercase hex). federation.dr asserts these
// equal the captured cosigned head (count == tree_size; root == smt_root).
func RebuiltProjectionState(t Target) (entryCount int, smtRootHex string, err error) {
	pg := pgContainer(t.Network)
	cntStr, ok := dockerx.PGQuery(pg, pgUser, t.DB, "SELECT count(*) FROM entry_index")
	if !ok {
		return 0, "", fmt.Errorf("query entry_index count against %s/%s", pg, t.DB)
	}
	cnt, cErr := strconv.Atoi(strings.TrimSpace(cntStr))
	if cErr != nil {
		return 0, "", fmt.Errorf("parse entry_index count %q: %w", cntStr, cErr)
	}
	root, ok := dockerx.PGQuery(pg, pgUser, t.DB, "SELECT encode(current_root, 'hex') FROM smt_root_state WHERE id = 1")
	if !ok {
		return 0, "", fmt.Errorf("query smt_root_state against %s/%s", pg, t.DB)
	}
	return cnt, strings.TrimSpace(root), nil
}

// auditorEnv is one auditor's deterministic env. Its OWN listener stays plain
// http (probed over the host port), but it pulls from the ledger over OPEN HTTPS
// — AUDITOR_PEERS is the https ledger URL; AUDITOR_PEER_ALLOW_SELF_SIGNED opens
// the peer client to server-verify-only (verify the ledger's self-signed cert
// against AUDITOR_PEER_CA_FILE, present NO client cert). The cosignature crypto,
// not the transport, is the trust.
func auditorEnv(nc NetConfig, in Infra, idx int) map[string]string {
	return map[string]string{
		"AUDITOR_LISTEN_ADDR":            ":8088",
		"AUDITOR_GOSSIP_DSN":             dsn(in.PG(), nc.GossipDB(idx)),
		"AUDITOR_NETWORK_BOOTSTRAP_FILE": mntFixtures + "/network-bootstrap.json",
		"AUDITOR_WITNESS_QUORUM_K":       strconv.Itoa(nc.Spec.QuorumK),
		"AUDITOR_ORIGINATOR_DISCOVERY":   "true",
		"AUDITOR_PEERS":                  nc.LogDID + "=https://" + nc.Name("ledger") + ":8080",
		"AUDITOR_PEER_CA_FILE":           mntCerts + "/ca.crt",
		"AUDITOR_PEER_ALLOW_SELF_SIGNED": "true",
		"AUDITOR_POLL_INTERVAL":          auditorPollInterval(),
		"AUDITOR_HORIZON_INTERVAL":       auditorHorizonInterval(),
		"AUDITOR_HORIZON_SAMPLES":        auditHorizonSamples(),
		// Independent equivocation detection (emit leg): the scanner signs the
		// findings it pushes to the ledger mesh under this gossip identity — minted
		// into the fixtures dir and declared as a genesis auditor, so its findings
		// are recognized by the always-on gate. Enabling both unblocks the
		// gate-routed finding flow end-to-end.
		"AUDITOR_GOSSIP_SIGNING_KEY":         mntFixtures + "/" + auditorGossipKeyFile,
		"AUDITOR_EQUIVOCATION_SCAN_INTERVAL": auditorScanInterval(),
	}
}

// UpAuditors brings up this network's auditors. Their gossip databases must already
// exist (the builder EnsureDB's them first). Each auditor pulls from the ledger
// over open HTTPS (server-verify, no client cert); its own probe listener stays
// plain http.
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

// jnEnv is the JN enforcer's deterministic env. Its OWN listener stays mTLS
// (API_AUTH_* — the JN authenticates ITS callers; it is the write gate). Its
// outbound leg to the ledger is OPEN HTTPS: API_LEDGER_ENDPOINT is the https
// ledger URL and API_LEDGER_ALLOW_SELF_SIGNED opens the client to server-verify
// (verify the ledger's self-signed cert against API_LEDGER_CA_FILE, present NO
// client cert) — the ledger accepts the JN's crypto-verified writes regardless of
// transport. The gossip-ingest peer is the auditor's plain-http feed, so it stays
// http.
func jnEnv(nc NetConfig) map[string]string {
	return map[string]string{
		"API_LISTEN_ADDR":              ":8443",
		"API_LEDGER_ENDPOINT":          "https://" + nc.Name("ledger") + ":8080",
		"API_LEDGER_CA_FILE":           mntCerts + "/ca.crt",
		"API_LEDGER_ALLOW_SELF_SIGNED": "true",
		"API_NETWORK_BOOTSTRAP_FILE":   mntFixtures + "/network-bootstrap.json",
		"API_WITNESS_QUORUM_K":         strconv.Itoa(nc.Spec.QuorumK),
		"API_GOSSIP_INGEST_ENABLED":    "true",
		"API_GOSSIP_INGEST_PEER_URL":   "http://" + nc.Name("auditor-1") + ":8088",
		"API_AUTH_CLIENT_CA_FILE":      mntCerts + "/ca.crt",
		"API_AUTH_TLS_CERT_FILE":       mntCerts + "/server.crt",
		"API_AUTH_TLS_KEY_FILE":        mntCerts + "/server.key",
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
// the ledger over OPEN HTTPS (TOOLS_LEDGER_URL https + TOOLS_LEDGER_ALLOW_SELF_SIGNED
// → server-verify against TOOLS_LEDGER_CA_FILE, no client cert) and indexes into
// its OWN projection DB; the three log DIDs all point at the network's bootstrap
// log. The aggregator is a read projection — open read + crypto is its trust.
func aggregatorEnv(nc NetConfig, in Infra) map[string]string {
	return map[string]string{
		"TOOLS_DATABASE_URL":             dsn(in.PG(), nc.AggDB),
		"TOOLS_LEDGER_URL":               "https://" + nc.Name("ledger") + ":8080",
		"TOOLS_LEDGER_CA_FILE":           mntCerts + "/ca.crt",
		"TOOLS_LEDGER_ALLOW_SELF_SIGNED": "true",
		"TOOLS_OFFICERS_LOG":             nc.LogDID,
		"TOOLS_CASES_LOG":                nc.LogDID,
		"TOOLS_PARTIES_LOG":              nc.LogDID,
	}
}

// UpAggregator brings up this network's read-projection aggregator (open-HTTPS
// outbound to the ledger, server-verify + no client cert; plain-http probe
// surface, so /healthz + /readyz are probed over plain http). Its projection DB
// must already exist (the builder EnsureDB's it first). /readyz is db+ledger-gated.
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
// the open-HTTPS ledger are reachable (the aggregator's probes.go), so a true
// result proves the read-projection's scan-pipeline wiring end-to-end.
func AggregatorReady(port int) bool {
	return httpStatus(fmt.Sprintf("http://localhost:%d/healthz", port)) == 200 &&
		httpStatus(fmt.Sprintf("http://localhost:%d/readyz", port)) == 200
}

// AuditorReady probes an auditor's plain-http /healthz then /readyz over its host
// port. This is more than a liveness ping: the auditor reaches /readyz only AFTER
// its boot-time originator discovery (AUDITOR_ORIGINATOR_DISCOVERY) GETs the
// ledger's /v1/log-info over OPEN HTTPS — server-verify against the run CA, NO
// client cert (AUDITOR_PEER_ALLOW_SELF_SIGNED). A failed handshake fails the
// pipeline build BEFORE the listener serves, so a green auditor is itself the
// auditor↔ledger open-HTTPS proof, end-to-end.
func AuditorReady(port int) bool {
	return httpStatus(fmt.Sprintf("http://localhost:%d/healthz", port)) == 200 &&
		httpStatus(fmt.Sprintf("http://localhost:%d/readyz", port)) == 200
}

// AuditorFeedServing reports whether the auditor's gossip custody feed (the JN's
// ingest source, /v1/gossip) is mounted and serving. Any reachable non-5xx status
// proves the SDK FeedHandler is wired over the auditor's open-HTTPS-fed custody
// store — i.e. the auditor is not just up, it is serving what it pulled.
func AuditorFeedServing(port int) bool {
	st := httpStatus(fmt.Sprintf("http://localhost:%d/v1/gossip/", port))
	return st != 0 && st < 500
}
