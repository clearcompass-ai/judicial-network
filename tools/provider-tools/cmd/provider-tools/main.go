/*
FILE PATH:

	tools/cmd/provider-tools/main.go

DESCRIPTION:

	Entry point for the provider-tools binary. Wires upstream
	services (ledger, verification API) and Postgres to the
	public-records HTTP server. Read-only — never touches the
	exchange (writes flow exclusively through the courts side).

KEY ARCHITECTURAL DECISIONS:
  - Aggregator NOT in-process: provider-tools serves only the
    cached state populated by court-tools' aggregator. Running
    a second aggregator here would double-poll the ledger;
    worse, write conflicts on the same Postgres tables would
    surface as duplicate-key errors. Provider-tools assumes
    court-tools is responsible for keeping Postgres up to date.
  - DB optional: if Postgres unreachable, HTTP server starts
    but read endpoints return 503. There is no degraded mode
    that bypasses the DB cache (would be too slow against the
    ledger for public-records traffic).
  - No exchange client: provider-tools is read-only. Background
    checks query Postgres + verification API only.
  - Fail-fast on config: missing or malformed config is fatal.

OVERVIEW:
 1. Parse flags → load config (JSON + env overrides).
 2. Construct HTTP client for verification API.
 3. Attempt Postgres connection. Log warning if unavailable.
 4. Start providers HTTP server on configured address.
 5. Block on SIGINT/SIGTERM → cancel context → clean shutdown.

KEY DEPENDENCIES:
  - tools/common: Config, VerifyClient, DB
  - tools/providers: Server (read-only HTTP handler tree)
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

	"github.com/baseproof/baseproof/storage"
	common "github.com/baseproof/tooling/libs/clitools"
	"github.com/clearcompass-ai/judicial-network/tools/provider-tools"
)

func main() {
	configPath := flag.String("config", "", "path to config JSON file")
	flag.Parse()

	// -------------------------------------------------------------------------
	// 1) Configuration
	// -------------------------------------------------------------------------

	cfg, err := common.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("FATAL: config: %v", err)
	}

	verify, err := buildVerifyClient(cfg)
	if err != nil {
		log.Fatalf("FATAL: verify client: %v", err)
	}

	// SDK v1.25.0: storage.HTTPContentStoreConfig requires Client; nil
	// cs ⇒ document-fetch handler surfaces 503.
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
		}
	}

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// -------------------------------------------------------------------------
	// 3) HTTP server
	// -------------------------------------------------------------------------

	srv := providers.NewServer(cfg, verify, db, cs)
	go func() {
		if e := srv.ListenAndServe(); e != nil {
			log.Fatalf("FATAL: provider-tools: %v", e)
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

// buildVerifyClient returns an mTLS-wired verify client when the
// operator has populated cfg.Verification{ClientCert,ClientKey}File,
// otherwise the plaintext (server-verify only) client. Fail-closed
// on any TLS-material error.
func buildVerifyClient(cfg common.Config) (*common.VerifyClient, error) {
	if cfg.VerificationMTLSConfigured() {
		return common.NewMTLSVerifyClient(cfg.VerificationURL, cfg.VerificationTLS())
	}
	return common.NewVerifyClient(cfg.VerificationURL), nil
}
