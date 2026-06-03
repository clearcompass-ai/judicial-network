/*
FILE PATH:

	tools/cmd/court-tools/main.go

DESCRIPTION:

	Entry point for the court-tools binary. Wires upstream services (ledger,
	exchange, verification API, artifact store) to the courts HTTP server and
	the log aggregator. Single process, two goroutines.

KEY ARCHITECTURAL DECISIONS:
  - Aggregator in-process: avoids separate deployment for small courts.
    --aggregator-only flag supports dedicated aggregator deployments.
  - DB optional: if Postgres unreachable, HTTP server starts but read
    endpoints return 503. Writes always work (routed through exchange).
  - Fail-fast on config: missing or malformed config is fatal.

OVERVIEW:
 1. Parse flags → load config (JSON + env overrides).
 2. Construct HTTP clients for exchange, ledger, verification API.
 3. Attempt Postgres connection. Log warning if unavailable.
 4. Start aggregator goroutine (polls ledger → writes Postgres).
 5. Start courts HTTP server on configured address.
 6. Block on SIGINT/SIGTERM → cancel context → clean shutdown.

KEY DEPENDENCIES:
  - tools/common: Config, ExchangeClient, LedgerClient, VerifyClient, DB
  - tools/courts: Server (HTTP handler tree)
  - tools/aggregator: Scanner (polling loop)
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

	_ "github.com/lib/pq" // postgres driver for the projection store (clitools.NewDB)

	"github.com/baseproof/baseproof/storage"
	libagg "github.com/clearcompass-ai/attesta-tools/libs/aggregator"
	common "github.com/clearcompass-ai/attesta-tools/libs/clitools"
	"github.com/clearcompass-ai/judicial-network/tools/aggregator"
	"github.com/clearcompass-ai/judicial-network/tools/court-tools"
)

func main() {
	configPath := flag.String("config", "", "path to config JSON file")
	aggregatorOnly := flag.Bool("aggregator-only", false, "run aggregator without HTTP server")
	flag.Parse()

	// -------------------------------------------------------------------------
	// 1) Configuration
	// -------------------------------------------------------------------------

	cfg, err := common.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("FATAL: config: %v", err)
	}

	// Upstream clients: mTLS when the operator configured cert+key for
	// each surface, plaintext (server-verify only) otherwise. Failures
	// to load TLS material are FATAL — a misconfigured mTLS deploy
	// must die at boot, not silently demote to plaintext.
	exchange, err := buildExchangeClient(cfg)
	if err != nil {
		log.Fatalf("FATAL: exchange client: %v", err)
	}
	ledger, err := buildLedgerClient(cfg)
	if err != nil {
		log.Fatalf("FATAL: ledger client: %v", err)
	}
	verify, err := buildVerifyClient(cfg)
	if err != nil {
		log.Fatalf("FATAL: verify client: %v", err)
	}

	// SDK v1.25.0: storage.HTTPContentStoreConfig requires Client; the
	// in-binary content store carries the same posture as the ledger
	// client. nil cs ⇒ artifact-store reads/writes surface 503.
	var cs *storage.HTTPContentStore
	if cfg.ArtifactStoreURL != "" {
		cs, err = storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{
			BaseURL: cfg.ArtifactStoreURL,
			Client:  &http.Client{Timeout: 30 * time.Second},
		})
		if err != nil {
			log.Fatalf("FATAL: content store: %v", err)
		}
	}

	// -------------------------------------------------------------------------
	// 2) Database (optional — degrades gracefully)
	// -------------------------------------------------------------------------

	var db *common.DB
	if cfg.DatabaseURL != "" {
		db, err = common.NewDB(cfg.DatabaseURL)
		if err != nil {
			log.Printf("WARNING: database unavailable: %v", err)
		} else {
			defer db.Close()
			// Self-migrate the (rebuildable) projection schema; on failure
			// degrade to no-DB so read endpoints surface 503 rather than
			// erroring against missing tables.
			if mErr := aggregator.Migrate(db); mErr != nil {
				log.Printf("WARNING: projection schema migrate failed: %v", mErr)
				db = nil
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// -------------------------------------------------------------------------
	// 3) Aggregator
	// -------------------------------------------------------------------------

	if db != nil {
		projector := aggregator.NewJudicialProjector(aggregator.NewIndexer(db))
		scanner := libagg.NewScanner(libagg.ScannerConfig{
			LogDIDs:      cfg.LogDIDs(),
			BatchSize:    cfg.AggregatorBatchSize,
			PollInterval: cfg.AggregatorPollInterval,
		}, ledger, db, projector, nil)
		go func() {
			if e := scanner.Run(ctx); e != nil {
				log.Printf("ERROR: aggregator: %v", e)
			}
		}()
		log.Printf("aggregator: started (poll=%s, batch=%d)",
			cfg.AggregatorPollInterval, cfg.AggregatorBatchSize)
	}

	if *aggregatorOnly {
		log.Println("court-tools: aggregator-only mode")
		awaitSignal(cancel)
		return
	}

	// -------------------------------------------------------------------------
	// 4) HTTP server
	// -------------------------------------------------------------------------

	srv := courts.NewServer(cfg, exchange, verify, db, cs)
	go func() {
		if e := srv.ListenAndServe(); e != nil {
			log.Fatalf("FATAL: court-tools: %v", e)
		}
	}()

	awaitSignal(cancel)
}

func awaitSignal(cancel context.CancelFunc) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	sig := <-ch
	log.Printf("received %v — shutting down", sig)
	cancel()
}

// buildExchangeClient returns an mTLS-wired client when the operator
// has populated cfg.Exchange{ClientCert,ClientKey}File, otherwise the
// plaintext (server-verify only) client. A misconfigured mTLS deploy
// (cert+key present but unreadable) returns (nil, err) so the caller
// can fail boot — silent demotion to plaintext is a confused-deputy
// bug the constructor refuses to commit.
func buildExchangeClient(cfg common.Config) (*common.ExchangeClient, error) {
	if cfg.ExchangeMTLSConfigured() {
		return common.NewMTLSExchangeClient(cfg.ExchangeURL, cfg.ExchangeTLS())
	}
	return common.NewExchangeClient(cfg.ExchangeURL), nil
}

func buildLedgerClient(cfg common.Config) (*common.LedgerClient, error) {
	if cfg.LedgerMTLSConfigured() {
		return common.NewMTLSLedgerClient(cfg.LedgerURL, cfg.LedgerTLS(), cfg.CasesLogDID)
	}
	return common.NewLedgerClient(cfg.LedgerURL, cfg.CasesLogDID)
}

func buildVerifyClient(cfg common.Config) (*common.VerifyClient, error) {
	if cfg.VerificationMTLSConfigured() {
		return common.NewMTLSVerifyClient(cfg.VerificationURL, cfg.VerificationTLS())
	}
	return common.NewVerifyClient(cfg.VerificationURL), nil
}
