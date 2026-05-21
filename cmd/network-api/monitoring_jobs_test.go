package main

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/clearcompass-ai/attesta/gossip"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/witness"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
)

// fakePrunableStore is a gossip.Store that also implements pruner; only
// Prune is exercised (the embedded nil Store would panic if any other
// method were called, which buildMonitoringScheduler never does).
type fakePrunableStore struct{ gossip.Store }

func (fakePrunableStore) Prune(context.Context, int) (int64, error) { return 0, nil }

func TestBuildMonitoringScheduler_DisabledReturnsNil(t *testing.T) {
	s, err := buildMonitoringScheduler(config.Operational{}, judicial.Dependencies{}, nil, nil, slog.Default())
	if err != nil {
		t.Fatalf("disabled must not error: %v", err)
	}
	if s != nil {
		t.Fatalf("disabled scheduler must be nil")
	}
}

func TestBuildMonitoringScheduler_PruneForDurableStore(t *testing.T) {
	cfg := config.Operational{Monitoring: config.MonitoringConfig{Enabled: true}}
	s, err := buildMonitoringScheduler(cfg, judicial.Dependencies{}, fakePrunableStore{}, nil, slog.Default())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !slices.Contains(s.JobNames(), "gossip_prune") {
		t.Fatalf("durable store must register gossip_prune; got %v", s.JobNames())
	}
}

func TestBuildMonitoringScheduler_InMemoryStoreNoPrune(t *testing.T) {
	cfg := config.Operational{Monitoring: config.MonitoringConfig{Enabled: true}}
	s, err := buildMonitoringScheduler(cfg, judicial.Dependencies{}, gossip.NewInMemoryStore(), nil, slog.Default())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if slices.Contains(s.JobNames(), "gossip_prune") {
		t.Fatalf("in-memory store is not prunable; gossip_prune must not register")
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
	s, err := buildMonitoringScheduler(cfg, deps, fakePrunableStore{}, nil, slog.Default())
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
	_, err := buildMonitoringScheduler(cfg, judicial.Dependencies{}, nil, nil, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "mirror") {
		t.Fatalf("want a mirror-deps error, got %v", err)
	}
}

type recordingPruner struct {
	called bool
	days   int
}

func (r *recordingPruner) Prune(_ context.Context, d int) (int64, error) {
	r.called = true
	r.days = d
	return 3, nil
}

func TestPruneJob_InvokesPruneWithRetention(t *testing.T) {
	rp := &recordingPruner{}
	alerts, err := pruneJob(rp, 30, slog.Default())(context.Background())
	if err != nil || alerts != nil {
		t.Fatalf("pruneJob = (%v, %v), want (nil, nil)", alerts, err)
	}
	if !rp.called || rp.days != 30 {
		t.Fatalf("Prune not called with retention 30: called=%v days=%d", rp.called, rp.days)
	}
}
