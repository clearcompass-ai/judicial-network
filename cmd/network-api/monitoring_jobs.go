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

	A check job registers only when its audit list is non-empty AND the deps it
	needs are wired. Gossip retention prune is the AUDITOR's job (it owns the
	durable store), not the JN enforcer's. The loops perform NO external
	alerting I/O — they evaluate the math and publish gauges.
*/
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	monitoring "github.com/baseproof/baseproof/monitoring"
	sdknetwork "github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	"github.com/clearcompass-ai/attesta-tools/libs/crosslog"
	jnmon "github.com/clearcompass-ai/attesta-tools/libs/monitoring"
	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
)

const (
	defaultMirrorInterval  = 5 * time.Minute
	defaultAnchorInterval  = time.Hour
	defaultSealingInterval = 24 * time.Hour
)

// buildMonitoringScheduler constructs the scheduler and registers the Core-3
// domain audit jobs (where configured + deps available). Returns (nil, nil)
// when monitoring is disabled. Gossip retention prune is the AUDITOR's job
// (it owns the durable store); the JN enforcer schedules only domain audits.
func buildMonitoringScheduler(
	cfg config.Operational,
	deps judicial.Dependencies,
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

	// D12 — URL drift audit (libs v1.29.0 monitoring.CheckURLDrift). Registers
	// only when ALL four conditions are met: URLDriftInterval > 0, the
	// AuthoritativeResolver is populated, the DID resolver is wired, and the
	// bootstrap LocalLogDID is known. Mirrors the attesta-tools auditor's
	// 4-condition gate (services/auditor/internal/app/app.go) — any missing
	// piece silently disables the job (it's purely advisory).
	if cfg.URLDriftInterval > 0 && deps.AuthoritativeResolver != nil && deps.Resolver != nil {
		localLogDID := deps.AuthoritativeResolver.MirrorManifest.LogDID
		if localLogDID != "" {
			if err := sched.Register(jnmon.Job{
				Name:     "url_drift_audit",
				Interval: cfg.URLDriftInterval,
				Run:      urlDriftJob(deps, localLogDID),
			}); err != nil {
				return nil, err
			}
		}
	}

	// Signature-policy compliance (libs CheckSignaturePolicyCompliance) — the
	// auditor half of the ledger's admission floor. Registers when the interval
	// is set AND a network bootstrap is configured (the genesis chain source).
	// Genesis-seeded + entry/head-empty today (the "wired and ready" posture);
	// the per-entry floor re-check activates with no rewiring once a live on-log
	// scan populates the source's Entries/Heads.
	if m.SignaturePolicyInterval > 0 && cfg.NetworkBootstrapFile != "" {
		doc, err := loadBootstrapDoc(cfg.NetworkBootstrapFile)
		if err != nil {
			return nil, fmt.Errorf("monitoring: signature-policy audit: load bootstrap: %w", err)
		}
		ids, err := doc.IDs()
		if err != nil {
			return nil, fmt.Errorf("monitoring: signature-policy audit: derive network id: %w", err)
		}
		src := genesisGovernanceSource(*doc, [32]byte(ids.NetworkID), logger)
		if err := sched.Register(jnmon.Job{
			Name:     "signature_policy_compliance",
			Interval: m.SignaturePolicyInterval,
			Run:      signaturePolicyJob(src),
		}); err != nil {
			return nil, err
		}
	}

	if sched.Len() == 0 {
		logger.Warn("monitoring: scheduler enabled but no domain audit specs configured")
	}
	return sched, nil
}

// genesisGovernanceSource builds the genesis-seeded GovernanceSource from the
// network bootstrap. The genesis records[0] of each governance chain are
// synthesized from doc (mirroring the ledger's admission genesis rule); a future
// on-log walker that scans amendments + admitted entries swaps in a populated
// snapshot here without touching the job. AsOf is the genesis tree size — the
// genesis-only chain resolves cleanly there.
func genesisGovernanceSource(doc sdknetwork.BootstrapDocument, networkID [32]byte, logger *slog.Logger) jnmon.GovernanceSource {
	gov := crosslog.GovernanceGenesisFromBootstrap(doc, doc.ExchangeDID, networkID)
	snap := jnmon.GovernanceSnapshot{
		Governance: crosslog.MaterializeGovernance(nil, gov, logger),
		AsOf:       types.LogPosition{LogDID: doc.ExchangeDID, Sequence: doc.GenesisTreeHead.TreeSize},
	}
	return func(_ context.Context) (jnmon.GovernanceSnapshot, error) {
		return snap, nil
	}
}

// signaturePolicyJob runs one signature-policy compliance cycle per tick — the
// auditor half of the ledger's admission floor. It re-derives the network
// SignaturePolicy via the SDK walker (network.ResolveSignaturePolicyAt) and
// flags any admitted entry whose valid-signature count is below
// min_signatures_per_entry — or whose scheme/cosign-scheme is not admitted — at
// the policy in effect at its position. A genesis-only, entry-empty snapshot
// resolves cleanly and raises nothing (the steady "wired and ready" state).
func signaturePolicyJob(src jnmon.GovernanceSource) jnmon.JobFunc {
	return func(ctx context.Context) ([]monitoring.Alert, error) {
		snap, err := src(ctx)
		if err != nil {
			return nil, err
		}
		return jnmon.CheckSignaturePolicyCompliance(ctx, jnmon.SignaturePolicyComplianceConfig{
			Records: snap.Governance.SignaturePolicies,
			Entries: snap.Entries,
			Heads:   snap.Heads,
			AsOf:    snap.AsOf,
		}, time.Now().UTC())
	}
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

// urlDriftJob runs one URL drift audit cycle per scheduler tick. The
// MaterializedSource closure reads the AuthoritativeResolver's CURRENT
// record slices — when an on-log walker lands and pushes new records into
// the resolver, the next tick picks them up without re-registering the job.
// Today (no walker) the closure returns a snapshot built from the file-
// loaded auditor registry + amendments, so the audit cross-checks the
// FindingsURLs against the DID resolver. Empty Endpoints + Labels yields a
// best-effort audit until the walker lands.
func urlDriftJob(deps judicial.Dependencies, localLogDID string) jnmon.JobFunc {
	source := func(_ context.Context) (crosslog.MaterializedNetwork, error) {
		// Read live record slices off the resolver so a future on-log
		// walker that swaps in new records (via SDK-internal mutation
		// or via a JN re-construct path) is picked up next tick.
		r := deps.AuthoritativeResolver
		return crosslog.MaterializedNetwork{
			Endpoints:  r.WitnessEndpointRecords,
			Labels:     r.WitnessLabelRecords,
			Auditors:   r.AuditorRegistryRecords,
			Amendments: r.AuditorScopeAmendmentRecords,
		}, nil
	}
	return func(ctx context.Context) ([]monitoring.Alert, error) {
		return jnmon.CheckURLDrift(ctx, jnmon.URLDriftAuditConfig{
			LocalLogDID:        localLogDID,
			MaterializedSource: source,
			Resolver:           deps.Resolver,
		}, slog.Default(), time.Now().UTC())
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
