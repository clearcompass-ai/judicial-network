package stack

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/clearcompass-ai/judicial-network/e2e/dockerx"
)

// parsePromGauge extracts a single gauge value from Prometheus text-exposition
// output: the value on the first non-comment line whose metric name is EXACTLY
// `name` (with or without a {labels} set). It handles integer and
// scientific-notation values and the OTEL exporter's otel_scope_* labels, and the
// exact-name match means a longer metric sharing the prefix (…_total, …_bucket)
// never matches. Pure + dependency-free so it is unit-tested without a live
// ledger.
func parsePromGauge(text, name string) (float64, bool) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || !strings.HasPrefix(line, name) {
			continue
		}
		rest := line[len(name):]
		if rest == "" {
			continue
		}
		switch rest[0] {
		case '{': // a label set — strip it
			j := strings.IndexByte(rest, '}')
			if j < 0 {
				continue
			}
			rest = rest[j+1:]
		case ' ', '\t': // the value follows directly
		default: // a longer metric name sharing this prefix — not the one asked for
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		return v, true
	}
	return 0, false
}

// scrapeGauge fetches the ledger's open-HTTPS /metrics (server-verify, no client
// cert) and parses one gauge.
func scrapeGauge(certsDir string, port int, name string) (float64, bool) {
	text := ledgerBody(certsDir, fmt.Sprintf("https://localhost:%d/metrics", port))
	return parsePromGauge(text, name)
}

// ScrapeGauge fetches one Prometheus gauge by exact name from the ledger's
// open-HTTPS /metrics (server-verify, no client cert). Exported so recipes (e.g.
// verify.tiling) read arbitrary ledger gauges over HTTPS.
func ScrapeGauge(certsDir string, port int, name string) (float64, bool) {
	return scrapeGauge(certsDir, port, name)
}

// WALDiskBytes returns baseproof_wal_disk_bytes (Badger LSM + value-log size) —
// the gauge verify.walgc watches stay BOUNDED as entries accumulate under GC.
func WALDiskBytes(certsDir string, port int) (int64, bool) {
	v, ok := scrapeGauge(certsDir, port, "baseproof_wal_disk_bytes")
	return int64(v), ok
}

// WALBacklog returns baseproof_wal_backlog_total (sequenced-but-not-shipped WAL
// depth). verify.walgc waits for it to reach 0 before measuring disk bytes so the
// reading reflects only the retained margin, not in-flight shipping.
func WALBacklog(certsDir string, port int) (int64, bool) {
	v, ok := scrapeGauge(certsDir, port, "baseproof_wal_backlog_total")
	return int64(v), ok
}

// RawEntryResolves reports whether GET /v1/entries/{seq}/raw resolves to bytes
// (following the 302 to the shared object store). After WAL GC a below-cutoff
// entry has NO WAL copy, so a non-empty body proves it still serves from the
// object store — the GC-safety contract.
func RawEntryResolves(certsDir string, port int, seq uint64) bool {
	return ledgerBody(certsDir, fmt.Sprintf("https://localhost:%d/v1/entries/%d/raw", port, seq)) != ""
}

// LedgerLogCount counts occurrences of substr in a container's logs — used to
// observe the deterministic "wal retention GC reclaimed" line, which the ledger
// logs ONLY when GC actually deletes entries.
func LedgerLogCount(name, substr string) int { return dockerx.LogCount(name, substr) }
