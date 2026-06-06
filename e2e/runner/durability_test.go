package runner

import "testing"

func TestParseGauges(t *testing.T) {
	body := []byte(`# HELP baseproof_wal_backlog_total Sequenced-but-not-shipped WAL depth.
# TYPE baseproof_wal_backlog_total gauge
baseproof_wal_backlog_total 0
# TYPE baseproof_horizon_lag_total gauge
baseproof_horizon_lag_total 12
baseproof_shipper_aimd_limit 6.8
baseproof_shipper_shipped_total 30000
baseproof_shipper_retries_total 4
# a labelled metric the parser must still key by bare name
baseproof_api_request_duration_seconds_count{route="*"} 99
unrelated_metric 1
`)
	g := parseGauges(body,
		"baseproof_wal_backlog_total",
		"baseproof_horizon_lag_total",
		"baseproof_shipper_aimd_limit",
		"baseproof_shipper_shipped_total",
		"baseproof_shipper_retries_total",
	)
	cases := map[string]float64{
		"baseproof_wal_backlog_total":     0,
		"baseproof_horizon_lag_total":     12,
		"baseproof_shipper_aimd_limit":    6.8,
		"baseproof_shipper_shipped_total": 30000,
		"baseproof_shipper_retries_total": 4,
	}
	for name, want := range cases {
		got, ok := g[name]
		if !ok {
			t.Errorf("%s not parsed", name)
			continue
		}
		if got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	if _, ok := g["unrelated_metric"]; ok {
		t.Error("unrelated_metric should not be collected")
	}
	if len(g) != len(cases) {
		t.Errorf("collected %d metrics, want %d", len(g), len(cases))
	}
}

// The backlog gauge being present (value 0) marks GaugesPresent; absence marks
// the pre-v0.0.19 image path. parseGauges drives that distinction.
func TestParseGauges_AbsentBacklog(t *testing.T) {
	body := []byte("baseproof_shipper_aimd_limit 64\n")
	g := parseGauges(body, "baseproof_wal_backlog_total", "baseproof_shipper_aimd_limit")
	if _, ok := g["baseproof_wal_backlog_total"]; ok {
		t.Error("absent backlog gauge must not appear")
	}
	if g["baseproof_shipper_aimd_limit"] != 64 {
		t.Errorf("aimd limit = %v, want 64", g["baseproof_shipper_aimd_limit"])
	}
}

func TestDurabilityLine(t *testing.T) {
	with := durabilityLine(durabilitySnapshot{GaugesPresent: true, Backlog: 0, HorizonLag: 0, AIMDLimit: 6.8, Shipped: 30000, Retries: 2})
	if want := "durability: backlog=0 lag=0 aimd=6.8 shipped=30000 retries=2"; with != want {
		t.Errorf("gauge line = %q, want %q", with, want)
	}
	without := durabilityLine(durabilitySnapshot{GaugesPresent: false})
	if without == "" || without == with {
		t.Errorf("pre-v0.0.19 line should differ + be non-empty, got %q", without)
	}
}
