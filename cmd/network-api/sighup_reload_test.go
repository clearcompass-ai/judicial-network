// D13 SIGHUP hot-reload tests.
//
// Pins:
//   1. runSIGHUPReload is a no-op when ReloadOnSIGHUP=false.
//   2. runSIGHUPReload short-circuits with a Warn when the
//      Reconciler is nil (no gossip ingest).
//   3. runSIGHUPReload short-circuits with a Warn when neither
//      file path is configured.
//   4. applyReload reads RegistryFile cleanly when present.
//   5. applyReload reads AmendmentFile cleanly when present.
//   6. applyReload retains the live snapshot for the failing file
//      and still refreshes the other — per-file fault tolerance.
//   7. applyReload returns cleanly when both file paths are empty.
package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/network"

	"github.com/clearcompass-ai/attesta-tools/libs/monitoring"

	"github.com/clearcompass-ai/judicial-network/api/config"
)

// quietSlog returns a logger that discards every event.
func quietSlog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// noopFindingVerifier satisfies monitoring.FindingVerifier without
// real work. The SIGHUP path never invokes Verify; this exists
// only so NewReconciler accepts the config.
type noopFindingVerifier struct{}

func (noopFindingVerifier) Verify(_ context.Context, _ gossip.SignedEvent) (gossip.Event, error) {
	return nil, nil
}

// newTestReconciler returns a Reconciler whose Refresh* methods
// install snapshots into the atomic.Pointer fields the scope gate
// reads. We don't drive Verify; the SIGHUP loop never invokes it.
func newTestReconciler(t *testing.T) *monitoring.Reconciler {
	t.Helper()
	rec, err := monitoring.NewReconciler(monitoring.ReconcilerConfig{
		Verifier: noopFindingVerifier{},
		Heads:    monitoring.NewTrustedHeadStore(quietSlog()),
		Logger:   quietSlog(),
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	return rec
}

func writeTempJSON(t *testing.T, name string, body any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// ─────────────────────────────────────────────────────────────────
// applyReload
// ─────────────────────────────────────────────────────────────────

// TestApplyReload_RegistryFile_Refreshed pins the happy path:
// applyReload reads RegistryFile and installs it via
// RefreshRegistry without logging an error.
func TestApplyReload_RegistryFile_Refreshed(t *testing.T) {
	t.Parallel()
	rec := newTestReconciler(t)
	cfg := config.Operational{}
	cfg.AuditorScope.RegistryFile = writeTempJSON(t, "registry.json",
		[]network.AuditorRegistrationRecord{})

	logger, calls := captureLogger()
	applyReload(cfg, rec, logger)

	if atomic.LoadInt32(&calls.errors) != 0 {
		t.Errorf("error logs = %d, want 0 (clean read)", atomic.LoadInt32(&calls.errors))
	}
	if atomic.LoadInt32(&calls.registryRefreshed) != 1 {
		t.Errorf("registryRefreshed = %d, want 1", atomic.LoadInt32(&calls.registryRefreshed))
	}
}

// TestApplyReload_AmendmentFile_Refreshed pins amendments parity
// with the registry path.
func TestApplyReload_AmendmentFile_Refreshed(t *testing.T) {
	t.Parallel()
	rec := newTestReconciler(t)
	cfg := config.Operational{}
	cfg.AuditorScope.AmendmentFile = writeTempJSON(t, "amendments.json",
		[]network.AuditorScopeAmendmentRecord{})

	logger, calls := captureLogger()
	applyReload(cfg, rec, logger)

	if atomic.LoadInt32(&calls.errors) != 0 {
		t.Errorf("error logs = %d, want 0 (clean read)", atomic.LoadInt32(&calls.errors))
	}
	if atomic.LoadInt32(&calls.amendmentRefreshed) != 1 {
		t.Errorf("amendmentRefreshed = %d, want 1", atomic.LoadInt32(&calls.amendmentRefreshed))
	}
}

// TestApplyReload_RegistryFailure_PreservesAmendments pins per-
// file fault tolerance: a broken RegistryFile is logged but does
// NOT prevent AmendmentFile from being refreshed.
func TestApplyReload_RegistryFailure_PreservesAmendments(t *testing.T) {
	t.Parallel()
	rec := newTestReconciler(t)
	cfg := config.Operational{}
	cfg.AuditorScope.RegistryFile = "/no/such/registry.json"
	cfg.AuditorScope.AmendmentFile = writeTempJSON(t, "amendments.json",
		[]network.AuditorScopeAmendmentRecord{})

	logger, calls := captureLogger()
	applyReload(cfg, rec, logger)

	if atomic.LoadInt32(&calls.errors) < 1 {
		t.Errorf("error logs = %d, want >=1 (registry read should fail)", atomic.LoadInt32(&calls.errors))
	}
	if atomic.LoadInt32(&calls.amendmentRefreshed) != 1 {
		t.Errorf("amendmentRefreshed = %d, want 1 (per-file fault tolerance)",
			atomic.LoadInt32(&calls.amendmentRefreshed))
	}
}

// TestApplyReload_EmptyConfig_NoOp pins defense-in-depth: even if
// runSIGHUPReload's short-circuit is bypassed, applyReload with
// no file paths returns cleanly.
func TestApplyReload_EmptyConfig_NoOp(t *testing.T) {
	t.Parallel()
	rec := newTestReconciler(t)
	cfg := config.Operational{}
	logger, calls := captureLogger()
	applyReload(cfg, rec, logger)
	if atomic.LoadInt32(&calls.errors) != 0 {
		t.Errorf("error logs = %d, want 0", atomic.LoadInt32(&calls.errors))
	}
}

// ─────────────────────────────────────────────────────────────────
// runSIGHUPReload — short-circuit cases
// ─────────────────────────────────────────────────────────────────

// TestRunSIGHUPReload_Disabled_NoHandler pins the default-off
// posture: ReloadOnSIGHUP=false returns immediately, no goroutine
// spawned (verified indirectly: no Warn logs).
func TestRunSIGHUPReload_Disabled_NoHandler(t *testing.T) {
	t.Parallel()
	cfg := config.Operational{}
	rec := newTestReconciler(t)
	logger, calls := captureLogger()
	runSIGHUPReload(context.Background(), cfg, rec, logger)
	if atomic.LoadInt32(&calls.warns) != 0 || atomic.LoadInt32(&calls.infos) != 0 {
		t.Errorf("disabled path emitted logs (warns=%d, infos=%d) — should be silent",
			atomic.LoadInt32(&calls.warns), atomic.LoadInt32(&calls.infos))
	}
}

// TestRunSIGHUPReload_NilReconciler_NoHandler pins the second
// short-circuit: when no home Reconciler is wired, reload is
// logged-and-skipped.
func TestRunSIGHUPReload_NilReconciler_NoHandler(t *testing.T) {
	t.Parallel()
	cfg := config.Operational{}
	cfg.AuditorScope.ReloadOnSIGHUP = true
	cfg.AuditorScope.RegistryFile = "/etc/registry.json"

	logger, calls := captureLogger()
	runSIGHUPReload(context.Background(), cfg, nil, logger)

	if atomic.LoadInt32(&calls.warns) != 1 {
		t.Errorf("warn logs = %d, want 1 (no-reconciler diagnosis)", atomic.LoadInt32(&calls.warns))
	}
}

// TestRunSIGHUPReload_NoFiles_NoHandler pins the third short-
// circuit: reload enabled + Reconciler wired BUT no files
// configured → logged-and-skipped.
func TestRunSIGHUPReload_NoFiles_NoHandler(t *testing.T) {
	t.Parallel()
	cfg := config.Operational{}
	cfg.AuditorScope.ReloadOnSIGHUP = true
	rec := newTestReconciler(t)

	logger, calls := captureLogger()
	runSIGHUPReload(context.Background(), cfg, rec, logger)

	if atomic.LoadInt32(&calls.warns) != 1 {
		t.Errorf("warn logs = %d, want 1 (no-files diagnosis)", atomic.LoadInt32(&calls.warns))
	}
}

// ─────────────────────────────────────────────────────────────────
// Capturing logger
// ─────────────────────────────────────────────────────────────────

type logCounts struct {
	warns              int32
	infos              int32
	errors             int32
	amendmentRefreshed int32
	registryRefreshed  int32
}

func captureLogger() (*slog.Logger, *logCounts) {
	counts := &logCounts{}
	h := &countingHandler{counts: counts}
	return slog.New(h), counts
}

type countingHandler struct{ counts *logCounts }

func (h *countingHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	switch r.Level {
	case slog.LevelWarn:
		atomic.AddInt32(&h.counts.warns, 1)
	case slog.LevelInfo:
		atomic.AddInt32(&h.counts.infos, 1)
	case slog.LevelError:
		atomic.AddInt32(&h.counts.errors, 1)
	}
	if r.Message == "network-api/sighup_reload: amendments refreshed" {
		atomic.AddInt32(&h.counts.amendmentRefreshed, 1)
	}
	if r.Message == "network-api/sighup_reload: registry refreshed" {
		atomic.AddInt32(&h.counts.registryRefreshed, 1)
	}
	return nil
}

func (h *countingHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(_ string) slog.Handler      { return h }
