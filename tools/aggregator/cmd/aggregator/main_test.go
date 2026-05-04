/*
FILE PATH: tools/cmd/aggregator/main_test.go

DESCRIPTION:
    Pins the aggregator binary's boot path:
      1. parseFlags surfaces a usable runArgs from typical input.
      2. run() rejects empty database_url + operator_url.
      3. run() boots, the probe server is reachable, the scanner
         goroutine starts, and SIGINT triggers a graceful shutdown.

    Tests use deps stubs to avoid real Postgres / operator
    dependencies — the boot wiring is what's under test, not the
    Scanner / DB internals (those have their own unit tests).
*/
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/tools/aggregator"
	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// ─────────────────────────────────────────────────────────────────────
// parseFlags
// ─────────────────────────────────────────────────────────────────────

func TestParseFlags_Defaults(t *testing.T) {
	args, err := parseFlags(nil)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if args.listenAddr != ":8092" {
		t.Errorf("listenAddr default = %q, want :8092", args.listenAddr)
	}
	if args.configPath != "" {
		t.Errorf("configPath default = %q, want empty", args.configPath)
	}
}

func TestParseFlags_Override(t *testing.T) {
	args, err := parseFlags([]string{"--config", "/etc/agg.json", "--listen-addr", "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if args.configPath != "/etc/agg.json" || args.listenAddr != "127.0.0.1:0" {
		t.Errorf("flags not applied: %+v", args)
	}
}

// ─────────────────────────────────────────────────────────────────────
// run() — config validation
// ─────────────────────────────────────────────────────────────────────

func writeAggCfg(t *testing.T, m map[string]any) string {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "agg.json")
	data, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return tmp
}

func TestRun_RejectsEmptyDatabaseURL(t *testing.T) {
	cfgPath := writeAggCfg(t, map[string]any{
		"operator_url": "http://op.test",
		"database_url": "",
	})
	err := run([]string{"--config", cfgPath}, deps{
		loadConfig: common.LoadConfig,
	})
	if !errors.Is(err, errMissingDB) {
		t.Errorf("err = %v, want errMissingDB", err)
	}
}

func TestRun_RejectsEmptyOperatorURL(t *testing.T) {
	cfgPath := writeAggCfg(t, map[string]any{
		"operator_url": "",
		"database_url": "postgres://localhost/x",
	})
	err := run([]string{"--config", cfgPath}, deps{
		loadConfig: common.LoadConfig,
	})
	if !errors.Is(err, errMissingOperator) {
		t.Errorf("err = %v, want errMissingOperator", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// run() — full boot smoke
// ─────────────────────────────────────────────────────────────────────

func TestRun_BootShutdownRoundTrip(t *testing.T) {
	// Free port for the probe server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfgPath := writeAggCfg(t, map[string]any{
		"operator_url": "http://op.test",
		"database_url": "postgres://test/test",
		"cases_log":    "did:web:test:cases",
	})

	// Stub deps so no real DB / operator is needed.
	stubDB := &fakeDB{}
	scannerStarted := make(chan struct{}, 1)
	stubDeps := deps{
		loadConfig: common.LoadConfig,
		openDB: func(_ string) (*common.DB, error) {
			// Return a real *common.DB shape with a stub Pool —
			// the aggregator's NewScanner doesn't actually use
			// the pool until the loop runs.
			return &common.DB{}, nil
		},
		newOperator: func(url, did string) *common.OperatorClient {
			return common.NewOperatorClient(url, did)
		},
		startScanner: func(ctx context.Context, _ *aggregator.Scanner) error {
			scannerStarted <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		},
		listenAndServ: func(srv *http.Server) error {
			return srv.ListenAndServe()
		},
	}

	runErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runErr <- run([]string{
			"--config", cfgPath,
			"--listen-addr", addr,
		}, stubDeps)
	}()

	// Scanner goroutine must start within 1s.
	select {
	case <-scannerStarted:
	case <-time.After(1 * time.Second):
		t.Fatal("scanner never started")
	}

	// Probe server must be reachable.
	if !waitFor(2*time.Second, func() bool {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}) {
		t.Fatal("/healthz never came up")
	}

	// SIGINT triggers shutdown.
	proc, _ := os.FindProcess(os.Getpid())
	_ = proc.Signal(syscall.SIGINT)

	select {
	case err := <-runErr:
		if err != nil {
			t.Errorf("run exited with %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not exit within 3s of signal")
	}
	wg.Wait()
	_ = stubDB
}

// fakeDB satisfies dbProber for boot tests where readyz isn't exercised.
type fakeDB struct{}

func (fakeDB) PingContext(_ context.Context) error { return nil }

func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// silence unused-import warnings for the test stubs.
var _ = strings.Contains
