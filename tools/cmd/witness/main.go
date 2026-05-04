/*
FILE PATH: tools/cmd/witness/main.go

DESCRIPTION:
    Standalone witness cosigning daemon. Closes the
    "operator self-signs unwitnessed in dev" gap from the
    walkthrough by running an independent cosignature loop:

      1. Periodically fetch the latest tree head from each
         configured operator endpoint via *witness.TreeHeadClient.
      2. Sign the canonical 40-byte WitnessCosignMessage with the
         daemon's BLS witness key.
      3. POST the cosignature back to the operator's witness-
         accept endpoint (default: <operator>/v1/cosignatures).

    The daemon is independent of any single court — operators run
    one daemon instance per witness identity, configured with the
    set of log DIDs it cosigns. Cross-tenant by construction.

    Probes (/healthz, /readyz, /metrics) follow the same pattern
    as the aggregator binary so cluster operators can scrape +
    monitor uniformly.

    What this daemon does NOT do:
      - Does not register the witness key on-chain. Witness key
        registration is governance-driven; the daemon assumes its
        public key is already in the operator's accepted-witness
        set.
      - Does not detect equivocation. The SDK has equivocation
        detection (witness/equivocation.go) but invoking it from
        a polling daemon requires a per-log historical store
        that's outside this binary's scope. Future commit.
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

	"github.com/clearcompass-ai/ortholog-sdk/witness"
)

// shutdownTimeout caps the probe-server drain on signal. Matches
// the aggregator's value.
const shutdownTimeout = 30 * time.Second

// runArgs bundles the parsed flags. parseFlags returns this so
// tests can build it without going through os.Args.
type runArgs struct {
	configPath string
	listenAddr string
}

func parseFlags(argv []string) (runArgs, error) {
	fs := flag.NewFlagSet("witness", flag.ContinueOnError)
	out := runArgs{}
	fs.StringVar(&out.configPath, "config", "", "path to witness config JSON file")
	fs.StringVar(&out.listenAddr, "listen-addr", ":8093",
		"address for the witness daemon's probe HTTP server")
	if err := fs.Parse(argv); err != nil {
		return runArgs{}, err
	}
	return out, nil
}

// deps abstracts the boot-time wiring so main_test.go can stub
// each step independently. The cosigning loop's signing function
// is split out as `signFn` so tests inject a deterministic stub
// instead of needing real BLS material.
type deps struct {
	loadConfig    func(string) (Config, error)
	signFn        SignerFunc
	postFn        CosigPostFunc
	listenAndServ func(*http.Server) error
}

func realDeps() deps {
	return deps{
		loadConfig:    LoadConfig,
		signFn:        defaultSignerFunc,
		postFn:        defaultPostFunc,
		listenAndServ: func(srv *http.Server) error { return srv.ListenAndServe() },
	}
}

func main() {
	if err := run(os.Args[1:], realDeps()); err != nil {
		log.Fatalf("witness: %v", err)
	}
}

// run is the testable entry point. main calls it with os.Args[1:]
// and realDeps; tests pass crafted args + stubs.
func run(argv []string, d deps) error {
	args, err := parseFlags(argv)
	if err != nil {
		return err
	}
	cfg, err := d.loadConfig(args.configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	endpoints := &witness.StaticEndpoints{
		Operators: cfg.Operators,
		Witnesses: map[string][]string{},
	}
	thc := witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())

	loop := newCosignLoop(cosignLoopConfig{
		LogDIDs:        cfg.LogDIDs,
		Operators:      cfg.Operators,
		PollInterval:   cfg.PollInterval,
		WitnessDID:     cfg.WitnessDID,
		Client:         thc,
		Signer:         d.signFn,
		Post:           d.postFn,
	})
	probes := newProbeHandlers(cfg)

	srv := &http.Server{
		Addr:              args.listenAddr,
		Handler:           probes.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loopErr := make(chan error, 1)
	go func() {
		log.Printf("witness: cosign loop started (poll=%s, logs=%v)",
			cfg.PollInterval, cfg.LogDIDs)
		loopErr <- loop.Run(ctx)
	}()

	probeErr := make(chan error, 1)
	go func() {
		log.Printf("witness: probes listening on %s", args.listenAddr)
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
		log.Printf("witness: %v received, shutting down", s)
	case err := <-loopErr:
		if err != nil {
			log.Printf("witness: cosign loop exited with %v", err)
		}
	case err := <-probeErr:
		if err != nil {
			log.Printf("witness: probe server exited with %v", err)
		}
	}
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("witness: probe shutdown: %v", err)
	}
	return nil
}
