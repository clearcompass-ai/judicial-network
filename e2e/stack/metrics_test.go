package stack

import "testing"

// sampleMetrics mimics the ledger's OTEL Prometheus exposition: HELP/TYPE
// comments, otel_scope_* labels, scientific-notation values, and sibling metrics
// that share a name prefix.
const sampleMetrics = `# HELP baseproof_wal_disk_bytes WAL on-disk size in bytes (Badger LSM + value-log).
# TYPE baseproof_wal_disk_bytes gauge
baseproof_wal_backlog_total{otel_scope_name="...wal",otel_scope_version="1.0"} 7
baseproof_wal_disk_bytes{otel_scope_name="...wal",otel_scope_version="1.0"} 1.234567e+06
baseproof_shipper_pending_total 0
target_info{service_name="ledger"} 1
`

func TestParsePromGauge_Table(t *testing.T) {
	cases := []struct {
		name string
		want float64
		ok   bool
	}{
		{"baseproof_wal_disk_bytes", 1234567, true},  // labels + scientific notation
		{"baseproof_wal_backlog_total", 7, true},     // labels + integer
		{"baseproof_shipper_pending_total", 0, true}, // no labels, zero
		{"baseproof_missing", 0, false},              // absent
		{"baseproof_wal_disk", 0, false},             // a PREFIX of a real metric — must not match
	}
	for _, c := range cases {
		got, ok := parsePromGauge(sampleMetrics, c.name)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("parsePromGauge(%q) = (%v, %v), want (%v, %v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestParsePromGauge_PlainValue(t *testing.T) {
	if v, ok := parsePromGauge("baseproof_wal_disk_bytes 4096", "baseproof_wal_disk_bytes"); !ok || v != 4096 {
		t.Fatalf("plain = (%v, %v), want (4096, true)", v, ok)
	}
}

func TestParsePromGauge_PrefixGuard(t *testing.T) {
	// A longer metric sharing the prefix must NOT be mistaken for the shorter name,
	// regardless of line order.
	text := "baseproof_wal_disk_bytes_total 99\nbaseproof_wal_disk_bytes 4096\n"
	if v, ok := parsePromGauge(text, "baseproof_wal_disk_bytes"); !ok || v != 4096 {
		t.Fatalf("prefix-guard = (%v, %v), want (4096, true) — must skip _total", v, ok)
	}
}

func TestParsePromGauge_CommentLinesIgnored(t *testing.T) {
	// HELP/TYPE comment lines mention the name but carry no value; the value line wins.
	text := "# HELP baseproof_wal_disk_bytes ...\n# TYPE baseproof_wal_disk_bytes gauge\nbaseproof_wal_disk_bytes 1\n"
	if v, ok := parsePromGauge(text, "baseproof_wal_disk_bytes"); !ok || v != 1 {
		t.Fatalf("comment-skip = (%v, %v), want (1, true)", v, ok)
	}
}

func TestParsePromGauge_EmptyAndMissing(t *testing.T) {
	if _, ok := parsePromGauge("", "baseproof_wal_disk_bytes"); ok {
		t.Fatal("empty text: want ok=false")
	}
	if _, ok := parsePromGauge("# only a comment\n", "baseproof_wal_disk_bytes"); ok {
		t.Fatal("no value line: want ok=false")
	}
}
