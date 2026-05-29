package main

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/did"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/log/discover"
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

// ──────────────────────────────────────────────────────────────────
// D12 — url_drift_audit 4-condition gate
//
// The job registers only when ALL four conditions hold:
//   1. cfg.URLDriftInterval > 0
//   2. deps.AuthoritativeResolver != nil
//   3. deps.Resolver != nil
//   4. resolver.MirrorManifest.LogDID != ""
//
// Any missing piece silently disables the job (it's purely advisory).
// One test per missing condition pins the gate's exact arms.
// ──────────────────────────────────────────────────────────────────

func TestBuildMonitoringScheduler_URLDrift_AllFourSet_Registers(t *testing.T) {
	cfg := config.Operational{
		Monitoring:       config.MonitoringConfig{Enabled: true},
		URLDriftInterval: time.Minute,
	}
	deps := judicial.Dependencies{
		Resolver: stubDIDResolver{},
		AuthoritativeResolver: &discover.DefaultAuthoritativeResolver{
			MirrorManifest: discover.MirrorManifest{LogDID: "did:web:jn-network"},
		},
	}
	s, err := buildMonitoringScheduler(cfg, deps, nil, slog.Default())
	if err != nil {
		t.Fatalf("buildMonitoringScheduler: %v", err)
	}
	if s == nil {
		t.Fatal("scheduler MUST be non-nil when monitoring enabled")
	}
	if !slices.Contains(s.JobNames(), "url_drift_audit") {
		t.Errorf("url_drift_audit MUST register when all 4 conditions hold; got %v", s.JobNames())
	}
}

// Condition 1 missing: URLDriftInterval == 0 → job disabled.
func TestBuildMonitoringScheduler_URLDrift_ZeroInterval_Disabled(t *testing.T) {
	cfg := config.Operational{
		Monitoring:       config.MonitoringConfig{Enabled: true},
		URLDriftInterval: 0, // condition 1 missing
	}
	deps := judicial.Dependencies{
		Resolver: stubDIDResolver{},
		AuthoritativeResolver: &discover.DefaultAuthoritativeResolver{
			MirrorManifest: discover.MirrorManifest{LogDID: "did:web:jn-network"},
		},
	}
	s, err := buildMonitoringScheduler(cfg, deps, nil, slog.Default())
	if err != nil {
		t.Fatalf("buildMonitoringScheduler: %v", err)
	}
	if s != nil && slices.Contains(s.JobNames(), "url_drift_audit") {
		t.Error("url_drift_audit MUST NOT register when URLDriftInterval==0")
	}
}

// Condition 2 missing: AuthoritativeResolver nil → job disabled.
func TestBuildMonitoringScheduler_URLDrift_NilResolver_Disabled(t *testing.T) {
	cfg := config.Operational{
		Monitoring:       config.MonitoringConfig{Enabled: true},
		URLDriftInterval: time.Minute,
	}
	deps := judicial.Dependencies{
		Resolver:              stubDIDResolver{},
		AuthoritativeResolver: nil, // condition 2 missing
	}
	s, err := buildMonitoringScheduler(cfg, deps, nil, slog.Default())
	if err != nil {
		t.Fatalf("buildMonitoringScheduler: %v", err)
	}
	if s != nil && slices.Contains(s.JobNames(), "url_drift_audit") {
		t.Error("url_drift_audit MUST NOT register when AuthoritativeResolver is nil")
	}
}

// Condition 3 missing: deps.Resolver (DID resolver) nil → job disabled.
func TestBuildMonitoringScheduler_URLDrift_NilDIDResolver_Disabled(t *testing.T) {
	cfg := config.Operational{
		Monitoring:       config.MonitoringConfig{Enabled: true},
		URLDriftInterval: time.Minute,
	}
	deps := judicial.Dependencies{
		Resolver: nil, // condition 3 missing
		AuthoritativeResolver: &discover.DefaultAuthoritativeResolver{
			MirrorManifest: discover.MirrorManifest{LogDID: "did:web:jn-network"},
		},
	}
	s, err := buildMonitoringScheduler(cfg, deps, nil, slog.Default())
	if err != nil {
		t.Fatalf("buildMonitoringScheduler: %v", err)
	}
	if s != nil && slices.Contains(s.JobNames(), "url_drift_audit") {
		t.Error("url_drift_audit MUST NOT register when DID resolver is nil")
	}
}

// Condition 4 missing: MirrorManifest.LogDID empty → job disabled.
func TestBuildMonitoringScheduler_URLDrift_EmptyLogDID_Disabled(t *testing.T) {
	cfg := config.Operational{
		Monitoring:       config.MonitoringConfig{Enabled: true},
		URLDriftInterval: time.Minute,
	}
	deps := judicial.Dependencies{
		Resolver: stubDIDResolver{},
		AuthoritativeResolver: &discover.DefaultAuthoritativeResolver{
			MirrorManifest: discover.MirrorManifest{LogDID: ""}, // condition 4 missing
		},
	}
	s, err := buildMonitoringScheduler(cfg, deps, nil, slog.Default())
	if err != nil {
		t.Fatalf("buildMonitoringScheduler: %v", err)
	}
	if s != nil && slices.Contains(s.JobNames(), "url_drift_audit") {
		t.Error("url_drift_audit MUST NOT register when MirrorManifest.LogDID is empty")
	}
}

// URL-drift coexists with the other 3 domain audits when all are
// configured — registration order does not gate the drift job.
func TestBuildMonitoringScheduler_URLDrift_CoexistsWithDomainJobs(t *testing.T) {
	cfg := config.Operational{
		Monitoring: config.MonitoringConfig{
			Enabled: true,
			Anchor:  []config.AnchorAuditConfig{{LocalLogDID: "did:x", ParentLogDID: "did:p", LedgerSignerDID: "did:s"}},
		},
		URLDriftInterval: time.Minute,
	}
	deps := judicial.Dependencies{
		TreeHeadClient: &witness.TreeHeadClient{},
		LogQueries:     map[string]sdklog.LedgerQueryAPI{"did:x": nil},
		Resolver:       stubDIDResolver{},
		AuthoritativeResolver: &discover.DefaultAuthoritativeResolver{
			MirrorManifest: discover.MirrorManifest{LogDID: "did:web:jn-network"},
		},
	}
	s, err := buildMonitoringScheduler(cfg, deps, nil, slog.Default())
	if err != nil {
		t.Fatalf("buildMonitoringScheduler: %v", err)
	}
	names := s.JobNames()
	wantNames := []string{"anchor_freshness", "url_drift_audit"}
	for _, want := range wantNames {
		if !slices.Contains(names, want) {
			t.Errorf("job %q MUST register; got %v", want, names)
		}
	}
}

// stubDIDResolver implements did.DIDResolver with a panic — the URL
// drift audit registration check only inspects deps.Resolver for
// non-nilness, never calls it.
type stubDIDResolver struct{}

func (stubDIDResolver) Resolve(_ context.Context, _ string) (*did.DIDDocument, error) {
	panic("stubDIDResolver.Resolve must not be called from the gate test")
}
