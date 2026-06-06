package runner

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

// Phase-2 durability validation: scrape the ledger's Prometheus /metrics, read
// the sustained-load gauges, and assert the pipeline drained and the durable
// witness-cosigned horizon caught up to the committed head. Degrades gracefully
// against a pre-v0.0.19 ledger image (the backlog/horizon-lag gauges are absent;
// the horizon-finalization check still runs).

// durabilitySnapshot is one read of the pipeline's durability state.
type durabilitySnapshot struct {
	HeadSize    int
	HeadSigs    int
	HorizonSize int
	HorizonSigs int

	// Phase-2 gauges (present iff the ledger image is v0.0.19+).
	Backlog       float64 // baseproof_wal_backlog_total
	HorizonLag    float64 // baseproof_horizon_lag_total
	AIMDLimit     float64 // baseproof_shipper_aimd_limit
	Shipped       float64 // baseproof_shipper_shipped_total
	Retries       float64 // baseproof_shipper_retries_total
	GaugesPresent bool
}

// scrapeLedgerGauges fetches /metrics and extracts the named no-label metrics.
func scrapeLedgerGauges(t stack.Target, names ...string) (map[string]float64, error) {
	ledger, err := caLedger(t)
	if err != nil {
		return nil, err
	}
	code, body, err := ledger.GetRaw("/metrics")
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("/metrics HTTP %d", code)
	}
	return parseGauges(body, names...), nil
}

// parseGauges extracts the named no-label metrics from a Prometheus text
// exposition. The metric name is the prefix up to the first '{' or space; the
// value is the last whitespace field. Comment (#) and blank lines are skipped.
func parseGauges(body []byte, names ...string) map[string]float64 {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	out := make(map[string]float64, len(names))
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		name := line
		if i := strings.IndexAny(line, "{ "); i >= 0 {
			name = line[:i]
		}
		if !want[name] {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if v, err := strconv.ParseFloat(fields[len(fields)-1], 64); err == nil {
			out[name] += v // singleton gauges ⇒ one value; sum is a no-op safety net
		}
	}
	return out
}

// snapshotDurability reads head + horizon (any image) and the Phase-2 gauges
// (v0.0.19+). Best-effort: a scrape error leaves the gauge fields zero and
// GaugesPresent false (the horizon check still gates).
func snapshotDurability(t stack.Target) durabilitySnapshot {
	var s durabilitySnapshot
	s.HeadSize, s.HeadSigs = stack.HeadStatus(t.CertsDir, t.LedgerPort)
	if c, err := stack.FetchHorizon(t.CertsDir, t.LedgerPort); err == nil {
		s.HorizonSize, s.HorizonSigs = c.TreeSize, len(c.Signatures)
	}
	g, err := scrapeLedgerGauges(t,
		"baseproof_wal_backlog_total",
		"baseproof_horizon_lag_total",
		"baseproof_shipper_aimd_limit",
		"baseproof_shipper_shipped_total",
		"baseproof_shipper_retries_total",
	)
	if err == nil {
		if v, ok := g["baseproof_wal_backlog_total"]; ok {
			s.Backlog = v
			s.GaugesPresent = true
		}
		s.HorizonLag = g["baseproof_horizon_lag_total"]
		s.AIMDLimit = g["baseproof_shipper_aimd_limit"]
		s.Shipped = g["baseproof_shipper_shipped_total"]
		s.Retries = g["baseproof_shipper_retries_total"]
	}
	return s
}

// assertDrained polls until the network is durably caught up at minSize, or the
// timeout elapses. "Caught up" = the witness-cosigned HORIZON has reached minSize
// with a K-of-N quorum AND (on a v0.0.19+ image) the WAL backlog and horizon lag
// have both drained to 0 — i.e. shipping and checkpointing kept up with ingest.
func assertDrained(t stack.Target, minSize int, timeout time.Duration) (durabilitySnapshot, error) {
	deadline := time.Now().Add(timeout)
	var last durabilitySnapshot
	for {
		last = snapshotDurability(t)
		horizonOK := last.HorizonSize >= minSize && last.HorizonSigs >= t.QuorumK
		// On a gauge-bearing image, also require the durability backlog to drain.
		gaugesOK := !last.GaugesPresent || (last.Backlog == 0 && last.HorizonLag == 0)
		if horizonOK && gaugesOK {
			return last, nil
		}
		if time.Now().After(deadline) {
			return last, fmt.Errorf(
				"not durably drained in %s: horizon=%d (want >=%d) sigs=%d (want K=%d) backlog=%.0f horizon_lag=%.0f",
				timeout, last.HorizonSize, minSize, last.HorizonSigs, t.QuorumK, last.Backlog, last.HorizonLag)
		}
		time.Sleep(2 * time.Second)
	}
}

// durabilityLine renders a one-line durability summary for the rung log.
func durabilityLine(s durabilitySnapshot) string {
	if !s.GaugesPresent {
		return "durability: horizon finalized (backlog/lag gauges absent — pre-v0.0.19 ledger image)"
	}
	return fmt.Sprintf("durability: backlog=%.0f lag=%.0f aimd=%.1f shipped=%.0f retries=%.0f",
		s.Backlog, s.HorizonLag, s.AIMDLimit, s.Shipped, s.Retries)
}
