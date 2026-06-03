package stack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/clearcompass-ai/judicial-network/e2e/dockerx"
)

// Mode-A credit identifiers (harness-owned: a bearer token + a credit-account DID,
// not protocol DIDs the ledger verifies cryptographically).
func creditToken() string       { return env("E2E_CREDIT_TOKEN", "baseproof-mode-a") }
func creditExchangeDID() string { return env("E2E_CREDIT_EXCHANGE_DID", "did:web:baseproof:exchange") }
func creditAmount() string      { return env("E2E_CREDITS", "1000000000") }

// Target is one network's addressable surface for seeding, workloads, and audit.
type Target struct {
	Network     string // docker network
	LedgerName  string // ledger container name (in-network URL)
	LedgerPort  int    // host port (health/head polls)
	LogDID      string
	QuorumK     int
	FixturesDir string // host fixtures dir (the /out + audit mount)
	Admission   string // credits|pow
}

func (t Target) innerURL() string { return "http://" + t.LedgerName + ":8080" }

// SeedOnUp makes the persisted stack immediately usable: it seeds Mode-A credits
// (when admission=credits), submits the genesis-seed entry, and waits for the
// K-cosigned head.
func SeedOnUp(in Infra, nc NetConfig, fixturesDir, ledgerImage string) error {
	if nc.Tuning.Admission == "credits" {
		if err := seedCredits(in, nc.DB); err != nil {
			return err
		}
	}
	t := nc.target(fixturesDir)
	if err := SubmitStamp(t, ledgerImage, "genesis-seed"); err != nil {
		return fmt.Errorf("seed submit: %w", err)
	}
	if !poll(120*time.Second, func() bool {
		sz, sigs := HeadStatus(nc.LedgerPort)
		return sz >= 1 && sigs >= nc.Spec.QuorumK
	}) {
		return fmt.Errorf("seed: tree head not cosigned (size>=1, sigs>=%d)", nc.Spec.QuorumK)
	}
	return nil
}

func (nc NetConfig) target(fixturesDir string) Target {
	return Target{
		Network: nc.Network, LedgerName: nc.Name("ledger"), LedgerPort: nc.LedgerPort,
		LogDID: nc.LogDID, QuorumK: nc.Spec.QuorumK, FixturesDir: fixturesDir, Admission: nc.Tuning.Admission,
	}
}

// seedCredits upserts a Mode-A bearer session + a write-credit balance (the two
// rows cmd/seed-session writes), so submissions skip PoW. Idempotent.
func seedCredits(in Infra, db string) error {
	did, tok, amt := creditExchangeDID(), creditToken(), creditAmount()
	q1 := fmt.Sprintf("INSERT INTO sessions (token, exchange_did, expires_at) "+
		"VALUES ('%s','%s',NOW()+INTERVAL '24 hours') "+
		"ON CONFLICT (token) DO UPDATE SET exchange_did=EXCLUDED.exchange_did, expires_at=EXCLUDED.expires_at;", tok, did)
	q2 := fmt.Sprintf("INSERT INTO credits (exchange_did, balance, total_purchased, updated_at) "+
		"VALUES ('%s',%s,%s,NOW()) "+
		"ON CONFLICT (exchange_did) DO UPDATE SET balance=credits.balance+%s, total_purchased=credits.total_purchased+%s, updated_at=NOW();",
		did, amt, amt, amt, amt)
	if _, ok := dockerx.PGQuery(in.PG(), pgUser, db, q1); !ok {
		return fmt.Errorf("seed session row")
	}
	if _, ok := dockerx.PGQuery(in.PG(), pgUser, db, q2); !ok {
		return fmt.Errorf("seed credit balance")
	}
	return nil
}

// SubmitStamp submits one commentary entry via the ledger image's /submit-stamp.
func SubmitStamp(t Target, ledgerImage, payload string) error {
	args := []string{"-url", t.innerURL(), "-log-did", t.LogDID, "-payload", payload}
	if t.Admission == "credits" {
		args = append(args, "-token", creditToken())
	}
	r := dockerx.Run(dockerx.RunSpec{
		Network: t.Network, Image: ledgerImage, Remove: true, Entrypoint: "/submit-stamp", ImageArgs: args,
	})
	if !r.OK() {
		return fmt.Errorf("submit-stamp %q: %s", payload, tail(r.Stderr, 300))
	}
	return nil
}

// HeadStatus reads /v1/tree/head → (tree_size, signature count) over the host port.
func HeadStatus(ledgerPort int) (int, int) {
	body := httpBody(fmt.Sprintf("http://localhost:%d/v1/tree/head", ledgerPort))
	if body == "" {
		return 0, 0
	}
	var h struct {
		TreeSize   int               `json:"tree_size"`
		Signatures []json.RawMessage `json:"signatures"`
	}
	if json.Unmarshal([]byte(body), &h) != nil {
		return 0, 0
	}
	return h.TreeSize, len(h.Signatures)
}

// LedgerHealthyPort probes /healthz over a host port.
func LedgerHealthyPort(ledgerPort int) bool {
	return httpBody(fmt.Sprintf("http://localhost:%d/healthz", ledgerPort)) == "ok"
}

// WaitDrained waits until the committed head reaches target tree_size.
func WaitDrained(ledgerPort, target int, timeout time.Duration) bool {
	return poll(timeout, func() bool { sz, _ := HeadStatus(ledgerPort); return sz >= target })
}

// BackfillStats is the subset of the backfill oracle manifest the runner asserts on.
type BackfillStats struct {
	Roots      int `json:"roots"`
	Amendments int `json:"amendments"`
	Leaves     []struct {
		Key string `json:"key"`
	} `json:"leaves"`
}

// Backfill loads n authority entries (roots + Path-A amendments) via the ledger
// image's /backfill, writing the oracle manifest into the network's fixtures dir.
// Output streams live (count/%/rate/ETA).
func Backfill(t Target, ledgerImage string, n, workers int, amendRatio float64, batchSize int) (*BackfillStats, error) {
	if workers < 1 {
		workers = 8
	}
	if batchSize < 1 {
		batchSize = 1
	}
	if batchSize > 1 && t.Admission != "credits" {
		return nil, fmt.Errorf("batch-size=%d requires admission=credits (Mode B PoW does not batch)", batchSize)
	}
	manifestHost := filepath.Join(t.FixturesDir, "backfill-manifest.json")
	_ = os.Remove(manifestHost) // start each load with a clean oracle
	args := []string{
		"-url", t.innerURL(), "-log-did", t.LogDID, "-n", strconv.Itoa(n),
		"-amend-ratio", fmt.Sprintf("%g", amendRatio), "-seed", "1",
		"-workers", strconv.Itoa(workers), "-manifest", mntOut + "/backfill-manifest.json",
	}
	if t.Admission == "credits" {
		args = append(args, "-token", creditToken())
	}
	if batchSize > 1 {
		args = append(args, "-batch-size", strconv.Itoa(batchSize), "-epoch", strconv.Itoa(max(64, workers*batchSize)))
	}
	bf := t.LedgerName + "-backfill"
	dockerx.Remove(bf)
	if r := dockerx.Run(dockerx.RunSpec{
		Name: bf, Network: t.Network, Image: ledgerImage, Detached: true, Entrypoint: "/backfill", User: uidGID(),
		Mounts: []dockerx.Mount{{Host: t.FixturesDir, Container: mntOut}}, ImageArgs: args,
	}); !r.OK() {
		return nil, fmt.Errorf("backfill start: %s", tail(r.Stderr, 300))
	}
	_ = dockerx.LogsFollow(bf)
	code := dockerx.Wait(bf)
	dockerx.Remove(bf)
	if code != "0" {
		return nil, fmt.Errorf("backfill exited %s — image predates /backfill, or the ledger WRITE path is stuck", code)
	}
	b, err := os.ReadFile(manifestHost)
	if err != nil {
		return nil, fmt.Errorf("backfill produced no manifest: %w", err)
	}
	var st BackfillStats
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("parse backfill manifest: %w", err)
	}
	return &st, nil
}

// RunAudit runs the stateless light-client auditor against the persisted stack's
// bootstrap and (optionally) the backfill oracle manifest. Returns the audit's
// stdout and nil iff the audit PASSes; the output is also surfaced live.
func RunAudit(t Target, ledgerImage string, samples, random int, withManifest bool) (string, error) {
	args := []string{
		"-url", t.innerURL(), "-bootstrap", mntFixtures + "/network-bootstrap.json",
		"-quorum", strconv.Itoa(t.QuorumK), "-samples", strconv.Itoa(samples), "-random", strconv.Itoa(random),
	}
	if withManifest {
		args = append(args, "-manifest", mntFixtures+"/backfill-manifest.json")
	}
	r := dockerx.Run(dockerx.RunSpec{
		Network: t.Network, Image: ledgerImage, Remove: true, Entrypoint: "/audit", User: uidGID(),
		Mounts: []dockerx.Mount{{Host: t.FixturesDir, Container: mntFixtures + ":ro"}}, ImageArgs: args,
	})
	if r.Stdout != "" {
		fmt.Print(r.Stdout)
	}
	if !r.OK() {
		return r.Stdout, fmt.Errorf("light-client audit FAILED:\n%s", tail(r.Stdout+r.Stderr, 800))
	}
	return r.Stdout, nil
}
