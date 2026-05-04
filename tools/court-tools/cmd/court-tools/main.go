/*
FILE PATH:
    tools/cmd/court-tools/main.go

DESCRIPTION:
    Entry point for the court-tools binary. Wires upstream services (operator,
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
    2. Construct HTTP clients for exchange, operator, verification API.
    3. Attempt Postgres connection. Log warning if unavailable.
    4. Start aggregator goroutine (polls operator → writes Postgres).
    5. Start courts HTTP server on configured address.
    6. Block on SIGINT/SIGTERM → cancel context → clean shutdown.

KEY DEPENDENCIES:
    - tools/common: Config, ExchangeClient, OperatorClient, VerifyClient, DB
    - tools/courts: Server (HTTP handler tree)
    - tools/aggregator: Scanner (polling loop)
*/
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/clearcompass-ai/judicial-network/tools/aggregator"
	"github.com/clearcompass-ai/judicial-network/tools/common"
	"github.com/clearcompass-ai/judicial-network/tools/courts"
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

	exchange := common.NewExchangeClient(cfg.ExchangeURL)
	operator := common.NewOperatorClient(cfg.OperatorURL, cfg.CasesLogDID)
	verify := common.NewVerifyClient(cfg.VerificationURL)

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
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// -------------------------------------------------------------------------
	// 3) Aggregator
	// -------------------------------------------------------------------------

	if db != nil {
		scanner := aggregator.NewScanner(cfg, operator, db)
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

	srv := courts.NewServer(cfg, exchange, verify, db)
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
