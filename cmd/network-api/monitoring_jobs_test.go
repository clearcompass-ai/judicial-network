package main

import (
	"log/slog"
	"slices"
	"strings"
	"testing"

	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/witness"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
)

func TestBuildMonitoringScheduler_DisabledReturnsNil(t *testing.T) {
	s, err := buildMonitoringScheduler(config.Operational{}, judicial.Dependencies{}, nil, slog.Default())
	if err != nil {
		t.Fatalf("disabled must not error: %v", err)
	}
	if s != nil {
		t.Fatalf("disabled scheduler must be nil")
	}
}

func TestBuildMonitoringScheduler_RegistersAnchorWhenConfigured(t *testing.T) {
	cfg := config.Operational{Monitoring: config.MonitoringConfig{
		Enabled: true,
		Anchor:  []config.AnchorAuditConfig{{LocalLogDID: "did:x", ParentLogDID: "did:p", LedgerSignerDID: "did:s"}},
	}}
	deps := judicial.Dependencies{
		TreeHeadClient: &witness.TreeHeadClient{},
		LogQueries:     map[string]sdklog.LedgerQueryAPI{"did:x": nil},
	}
	s, err := buildMonitoringScheduler(cfg, deps, nil, slog.Default())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !slices.Contains(s.JobNames(), "anchor_freshness") {
		t.Fatalf("anchor_freshness must register; got %v", s.JobNames())
	}
}

func TestBuildMonitoringScheduler_MirrorMissingDepsErrors(t *testing.T) {
	cfg := config.Operational{Monitoring: config.MonitoringConfig{
		Enabled: true,
		Mirror:  []config.MirrorAuditConfig{{OfficersLogDID: "did:o", CasesLogDID: "did:c"}},
	}}
	// No Fetcher/LeafReader/LogQueries wired ⇒ misconfiguration aborts boot.
	_, err := buildMonitoringScheduler(cfg, judicial.Dependencies{}, nil, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "mirror") {
		t.Fatalf("want a mirror-deps error, got %v", err)
	}
}
