/*
FILE PATH: cmd/network-api/monitoring_jobs.go

DESCRIPTION:

	Composition root for the continuous-monitoring scheduler — the JN's
	autonomous audit pulse. Turns the on-demand Check* functions (also
	served at /v1/judicial/monitoring/*) into scheduled, panic-recovered
	audits whose results are cached O(1) and published as OTel gauges.

	One network-wide job per check iterates the operator-configured audit
	specs and aggregates their alerts:

	  mirror_consistency (5m)  — local projection vs ledger TreeSize (Read)
	  anchor_freshness   (1h)  — cross-jurisdiction anchor lag    (Cross-Log)
	  sealing_compliance (24h) — sealed records physically blinded (Domain)

	Plus gossip_prune (24h): enforces the durable store's retention TTL.

	A check job registers only when its audit list is non-empty AND the
	deps it needs are wired; gossip_prune registers only when the store is
	durable (the in-memory store is not prunable). The loops perform NO
	external alerting I/O — they evaluate the math and publish gauges.
*/
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/clearcompass-ai/attesta/gossip"
	monitoring "github.com/clearcompass-ai/attesta/monitoring"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/witness"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
	jnmon "github.com/clearcompass-ai/judicial-network/monitoring"
)

const (
	defaultMirrorInterval  = 5 * time.Minute
	defaultAnchorInterval  = time.Hour
	defaultSealingInterval = 24 * time.Hour
	defaultPruneInterval   = 24 * time.Hour
	defaultRetentionDays   = 30
)

// pruner is the subset of the durable store the prune job needs. The
// in-memory store does not implement it, so gossip_prune self-gates on a
// type assertion.
type pruner interface {
	Prune(ctx context.Context, retentionDays int) (int64, error)
}

// buildMonitoringScheduler constructs the scheduler and registers the
// Core-3 audit jobs (where configured + deps available) plus the gossip
// retention prune (D8). Returns (nil, nil) when monitoring is disabled.
func buildMonitoringScheduler(
	cfg config.Operational,
	deps judicial.Dependencies,
	store gossip.Store,
	sink jnmon.Sink,
	logger *slog.Logger,
) (*jnmon.Scheduler, error) {
	if !cfg.Monitoring.Enabled {
		return nil, nil
	}
	sched := jnmon.NewScheduler(jnmon.SchedulerConfig{Sink: sink, Logger: logger})
	m := cfg.Monitoring

	if len(m.Mirror) > 0 {
		if deps.Fetcher == nil || deps.LeafReader == nil || len(deps.LogQueries) == 0 {
			return nil, fmt.Errorf("monitoring: mirror audits configured but LogQueries/Fetcher/LeafReader unwired (set LedgerEndpoint)")
		}
		if err := sched.Register(jnmon.Job{
			Name:     "mirror_consistency",
			Interval: orDefault(m.MirrorInterval, defaultMirrorInterval),
			Run:      mirrorJob(deps, m.Mirror),
		}); err != nil {
			return nil, err
		}
	}

	if len(m.Anchor) > 0 {
		if deps.TreeHeadClient == nil || len(deps.LogQueries) == 0 {
			return nil, fmt.Errorf("monitoring: anchor audits configured but TreeHeadClient/LogQueries unwired")
		}
		if err := sched.Register(jnmon.Job{
			Name:     "anchor_freshness",
			Interval: orDefault(m.AnchorInterval, defaultAnchorInterval),
			Run:      anchorJob(deps, m.Anchor),
		}); err != nil {
			return nil, err
		}
	}

	if len(m.Sealing) > 0 {
		if deps.Fetcher == nil || deps.LeafReader == nil || deps.Extractor == nil || len(deps.LogQueries) == 0 {
			return nil, fmt.Errorf("monitoring: sealing audits configured but LogQueries/Fetcher/LeafReader/Extractor unwired")
		}
		if err := sched.Register(jnmon.Job{
			Name:     "sealing_compliance",
			Interval: orDefault(m.SealingInterval, defaultSealingInterval),
			Run:      sealingJob(deps, m.Sealing),
		}); err != nil {
			return nil, err
		}
	}

	if p, ok := store.(pruner); ok {
		days := cfg.GossipStore.RetentionDays
		if days <= 0 {
			days = defaultRetentionDays
		}
		if err := sched.Register(jnmon.Job{
			Name:     "gossip_prune",
			Interval: orDefault(m.PruneInterval, defaultPruneInterval),
			Run:      pruneJob(p, days, logger),
		}); err != nil {
			return nil, err
		}
	}

	if sched.Len() == 0 {
		logger.Warn("monitoring: scheduler enabled but no jobs registered (no audit specs and a non-durable store)")
	}
	return sched, nil
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// mirrorJob audits every configured officers→cases mirror pair.
func mirrorJob(deps judicial.Dependencies, specs []config.MirrorAuditConfig) jnmon.JobFunc {
	return func(ctx context.Context) ([]monitoring.Alert, error) {
		var all []monitoring.Alert
		var errs error
		for _, s := range specs {
			officers := deps.LogQueries[s.OfficersLogDID]
			cases := deps.LogQueries[s.CasesLogDID]
			if officers == nil || cases == nil {
				errs = errors.Join(errs, fmt.Errorf("mirror: missing LogQueries for %s/%s", s.OfficersLogDID, s.CasesLogDID))
				continue
			}
			alerts, err := jnmon.CheckMirrorConsistency(ctx, jnmon.MirrorConsistencyConfig{
				RootEntityPos:   types.LogPosition{LogDID: s.RootEntityLogDID, Sequence: s.RootEntitySequence},
				OfficersLogDID:  s.OfficersLogDID,
				CasesLogDID:     s.CasesLogDID,
				MirrorSignerDID: s.MirrorSignerDID,
			}, officers, cases, deps.Fetcher, deps.LeafReader, time.Now().UTC())
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}
			all = append(all, alerts...)
		}
		return all, errs
	}
}

// anchorJob audits every configured county→parent anchor relationship.
func anchorJob(deps judicial.Dependencies, specs []config.AnchorAuditConfig) jnmon.JobFunc {
	return func(ctx context.Context) ([]monitoring.Alert, error) {
		var all []monitoring.Alert
		var errs error
		for _, s := range specs {
			q := deps.LogQueries[s.LocalLogDID]
			if q == nil {
				errs = errors.Join(errs, fmt.Errorf("anchor: missing LogQueries for %s", s.LocalLogDID))
				continue
			}
			alerts, err := jnmon.CheckAnchorFreshness(ctx, jnmon.AnchorFreshnessConfig{
				LocalLogDID:          s.LocalLogDID,
				ParentLogDID:         s.ParentLogDID,
				LedgerSignerDID:      s.LedgerSignerDID,
				AnchorIntervalTarget: time.Hour,
				WarningThreshold:     90 * time.Minute,
				CriticalThreshold:    3 * time.Hour,
				ParentStaleness:      witness.StalenessMonitoring,
			}, q, deps.TreeHeadClient, time.Now().UTC())
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}
			all = append(all, alerts...)
		}
		return all, errs
	}
}

// sealingJob audits every configured local log's sealing compliance.
func sealingJob(deps judicial.Dependencies, specs []config.SealingAuditConfig) jnmon.JobFunc {
	return func(ctx context.Context) ([]monitoring.Alert, error) {
		var all []monitoring.Alert
		var errs error
		for _, s := range specs {
			q := deps.LogQueries[s.LocalLogDID]
			if q == nil {
				errs = errors.Join(errs, fmt.Errorf("sealing: missing LogQueries for %s", s.LocalLogDID))
				continue
			}
			alerts, err := jnmon.CheckSealingCompliance(ctx, jnmon.SealingComplianceConfig{
				LocalLogDID:  s.LocalLogDID,
				ScanStartSeq: s.ScanStartSeq,
				ScanCount:    s.ScanCount,
			}, q, deps.Fetcher, deps.LeafReader, deps.Extractor, time.Now().UTC())
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}
			all = append(all, alerts...)
		}
		return all, errs
	}
}

// pruneJob enforces the durable store's retention TTL (D8).
func pruneJob(p pruner, retentionDays int, logger *slog.Logger) jnmon.JobFunc {
	return func(ctx context.Context) ([]monitoring.Alert, error) {
		n, err := p.Prune(ctx, retentionDays)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			logger.Info("monitoring: pruned expired gossip events",
				slog.Int64("rows", n), slog.Int("retention_days", retentionDays))
		}
		return nil, nil
	}
}
