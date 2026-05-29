/*
FILE PATH: cmd/network-api/sighup_reload.go

DESCRIPTION:

	D13 — SIGHUP hot-reload of the v1.33.x auditor-scope gate
	inputs: AuditorRegistry + AuditorAmendments. Consumes the
	libs/monitoring.Reconciler RefreshRegistry / RefreshAmendments
	methods that wrap the two atomic.Pointer fields, so a reload
	swaps the snapshots without bouncing the binary and without
	a single reader-side mutex bounce.

	The operator-facing surface is a single env var
	(API_RELOAD_ON_SIGHUP, default false) and a single signal
	(syscall.SIGHUP). When the env var is true AND the home
	Reconciler is wired AND at least one of RegistryFile /
	AmendmentFile is configured, runSIGHUPReload registers the
	handler and the binary re-reads both files on every SIGHUP.

	PER-FILE FAULT TOLERANCE. A read-or-parse error on one file
	does NOT clobber the live snapshot for the other. The live
	snapshot for the failing file stays in place; the error is
	logged with structured context. This is the libs-side
	"do NOT install a partial snapshot" contract — the Reconciler's
	Refresh* methods accept nil to mean "disable the gate," not
	"clear the snapshot to a partial state."

	NO-OP ON BAD CONFIG. If a deployment ships SIGHUP reload ON
	but has no registry/amendment files configured (the operator
	relies on Materialized network records to populate the
	resolver), the reload is a logged-and-ignored no-op. This is
	the same "default OFF, operator opt-in via manifest"
	philosophy as the rest of the v1.33.x adoption surface.

	LIVENESS: blocks on the supplied context — exits when ctx is
	cancelled. Runs in a goroutine that survives until shutdown.
*/
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/clearcompass-ai/attesta-tools/libs/monitoring"

	"github.com/clearcompass-ai/judicial-network/api/config"
)

// runSIGHUPReload starts the SIGHUP listener. Returns immediately
// when reload-on-SIGHUP is disabled OR the Reconciler is nil OR
// neither file path is configured (logged as "no reload sources").
// Otherwise spawns a goroutine that loops on SIGHUP until ctx is
// cancelled.
//
// reconciler: the home-network Reconciler whose RefreshRegistry +
// RefreshAmendments methods install the new snapshots. Per-foreign
// reconcilers are not surfaced (foreign networks own their own
// authority graphs — see cmd/network-api/gossip_reconciler.go).
//
// cfg.AuditorScope is the source of truth for the two file paths
// AND the enable flag.
//
// logger threads structured events for every reload attempt:
// success, per-file error, no-op.
func runSIGHUPReload(
	ctx context.Context,
	cfg config.Operational,
	reconciler *monitoring.Reconciler,
	logger *slog.Logger,
) {
	if !cfg.AuditorScope.ReloadOnSIGHUP {
		return
	}
	if reconciler == nil {
		logger.Warn("network-api/sighup_reload: ReloadOnSIGHUP enabled but no home Reconciler wired (no gossip ingest? no home peers?); SIGHUP handler not registered")
		return
	}
	if cfg.AuditorScope.RegistryFile == "" && cfg.AuditorScope.AmendmentFile == "" {
		logger.Warn("network-api/sighup_reload: ReloadOnSIGHUP enabled but no RegistryFile or AmendmentFile configured; SIGHUP handler not registered (would be a no-op)")
		return
	}

	go reloadLoop(ctx, cfg, reconciler, logger)
}

// reloadLoop is the body of the SIGHUP handler. Factored out so
// tests can drive it with a synthetic channel + context without
// shipping a real signal.
func reloadLoop(
	ctx context.Context,
	cfg config.Operational,
	reconciler *monitoring.Reconciler,
	logger *slog.Logger,
) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	defer close(sigCh)

	logger.Info("network-api/sighup_reload: SIGHUP reload registered",
		slog.String("registry_file", cfg.AuditorScope.RegistryFile),
		slog.String("amendment_file", cfg.AuditorScope.AmendmentFile),
	)

	for {
		select {
		case <-ctx.Done():
			logger.Info("network-api/sighup_reload: shutdown — SIGHUP handler stopped")
			return
		case <-sigCh:
			applyReload(cfg, reconciler, logger)
		}
	}
}

// applyReload performs ONE reload pass: re-reads both files (each
// independently) and installs the new snapshots via the
// Reconciler's atomic.Pointer-backed Refresh methods. Per-file
// failures are logged AND do NOT touch the live snapshot for that
// file — keep-live-on-failure is the libs-side contract.
func applyReload(
	cfg config.Operational,
	reconciler *monitoring.Reconciler,
	logger *slog.Logger,
) {
	logger.Info("network-api/sighup_reload: SIGHUP received — re-reading auditor scope files")

	if cfg.AuditorScope.RegistryFile != "" {
		regs, err := loadAuditorRegistry(cfg.AuditorScope.RegistryFile)
		if err != nil {
			logger.Error("network-api/sighup_reload: registry re-read failed; live snapshot retained",
				slog.String("file", cfg.AuditorScope.RegistryFile),
				slog.String("error", err.Error()),
			)
		} else {
			reconciler.RefreshRegistry(regs)
			logger.Info("network-api/sighup_reload: registry refreshed",
				slog.String("file", cfg.AuditorScope.RegistryFile),
				slog.Int("records", len(regs)),
			)
		}
	}

	if cfg.AuditorScope.AmendmentFile != "" {
		amends, err := loadAuditorAmendments(cfg.AuditorScope.AmendmentFile)
		if err != nil {
			logger.Error("network-api/sighup_reload: amendments re-read failed; live snapshot retained",
				slog.String("file", cfg.AuditorScope.AmendmentFile),
				slog.String("error", err.Error()),
			)
		} else {
			reconciler.RefreshAmendments(amends)
			logger.Info("network-api/sighup_reload: amendments refreshed",
				slog.String("file", cfg.AuditorScope.AmendmentFile),
				slog.Int("records", len(amends)),
			)
		}
	}
}
