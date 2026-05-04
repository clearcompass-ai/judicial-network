/*
FILE PATH: tools/cmd/aggregator/main.go

DESCRIPTION:
    Standalone aggregator binary. Polls the operator for new
    entries on the registered logs (officers / cases / parties),
    classifies + indexes them into Postgres, and exposes a small
    HTTP probe surface (/healthz, /readyz, /metrics) for k8s
    liveness + Prometheus scraping.

    Distinct from court-tools' --aggregator-only mode: this binary
    has NO read-side HTTP query endpoints. Query traffic for the
    aggregator's Postgres state belongs in court-tools or
    provider-tools, which can be scaled separately. The aggregator
    is a write-only ingestion service against its own database.

    Boot order:
      1. Parse flags + load tools/common.Config (JSON + env override).
      2. Construct OperatorClient + DB.
      3. Start aggregator.Scanner in a goroutine.
      4. Stand up the probe HTTP server.
      5. Block on SIGINT / SIGTERM → cancel context → drain.

    The probe server uses the Phase 15 observability primitives
    (Prometheus registry + zerolog) so deployment-time scraping +
    logging are uniform with cmd/network-api.
*/
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/clearcompass-ai/judicial-network/tools/aggregator"
	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// deps abstracts the boot-time wiring so main_test.go can stub each
// step independently. realDeps points at the production wiring;
// tests substitute fakes.
type deps struct {
	loadConfig    func(string) (common.Config, error)
	openDB        func(string) (*common.DB, error)
	newOperator   func(string, string) *common.OperatorClient
	startScanner  func(context.Context, *aggregator.Scanner) error
	listenAndServ func(*http.Server) error
}

func realDeps() deps {
	return deps{
		loadConfig:    common.LoadConfig,
		openDB:        common.NewDB,
		newOperator:   func(url, did string) *common.OperatorClient { return common.NewOperatorClient(url, did) },
		startScanner:  func(ctx context.Context, s *aggregator.Scanner) error { return s.Run(ctx) },
		listenAndServ: func(srv *http.Server) error { return srv.ListenAndServe() },
	}
}

// shutdownTimeout caps how long the binary waits for the probe
// server to drain after a SIGINT / SIGTERM.
const shutdownTimeout = 30 * time.Second

func main() {
	if err := run(os.Args[1:], realDeps()); err != nil {
		log.Fatalf("aggregator: %v", err)
	}
}

// runArgs bundles the flag-parsed values so tests can build them
// without going through os.Args.
type runArgs struct {
	configPath string
	listenAddr string
}

func parseFlags(argv []string) (runArgs, error) {
	fs := flag.NewFlagSet("aggregator", flag.ContinueOnError)
	out := runArgs{}
	fs.StringVar(&out.configPath, "config", "", "path to tools config JSON file")
	fs.StringVar(&out.listenAddr, "listen-addr", ":8092",
		"address for the aggregator's probe HTTP server (/healthz, /readyz, /metrics)")
	if err := fs.Parse(argv); err != nil {
		return runArgs{}, err
	}
	return out, nil
}

// run is the testable entry point. main calls it with os.Args[1:]
// and realDeps; tests pass crafted args + stubs.
//
// Returns nil on graceful shutdown (signal received, scanner +
// probe server drained). Returns a wrapped error on any boot or
// runtime failure that aborts the process.
func run(argv []string, d deps) error {
	args, err := parseFlags(argv)
	if err != nil {
		return err
	}

	cfg, err := d.loadConfig(args.configPath)
	if err != nil {
		return err
	}
	if cfg.DatabaseURL == "" {
		return errMissingDB
	}
	if cfg.OperatorURL == "" {
		return errMissingOperator
	}

	db, err := d.openDB(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	operator := d.newOperator(cfg.OperatorURL, cfg.CasesLogDID)
	scanner := aggregator.NewScanner(cfg, operator, db)
	probes := newProbeHandlers(db, cfg.OperatorURL)

	srv := &http.Server{
		Addr:              args.listenAddr,
		Handler:           probes.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scannerErr := make(chan error, 1)
	go func() {
		log.Printf("aggregator: scanner started (poll=%s, batch=%d, logs=%v)",
			cfg.AggregatorPollInterval, cfg.AggregatorBatchSize, cfg.LogDIDs())
		scannerErr <- d.startScanner(ctx, scanner)
	}()

	probeErr := make(chan error, 1)
	go func() {
		log.Printf("aggregator: probes listening on %s", args.listenAddr)
		err := d.listenAndServ(srv)
		if err != http.ErrServerClosed {
			probeErr <- err
			return
		}
		probeErr <- nil
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case s := <-sig:
		log.Printf("aggregator: %v received, shutting down", s)
	case err := <-scannerErr:
		if err != nil {
			log.Printf("aggregator: scanner exited with %v", err)
		}
	case err := <-probeErr:
		if err != nil {
			log.Printf("aggregator: probe server exited with %v", err)
		}
	}
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("aggregator: probe shutdown: %v", err)
	}
	return nil
}
