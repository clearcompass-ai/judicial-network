/*
FILE PATH: cmd/scenario/main.go

DESCRIPTION:

	`scenario` provisions a realistic judicial population + case lifecycle onto a
	live ledger over HTTP — the same wire every baseproof submit tool speaks
	(POST /v1/entries, poll /v1/entries-hash). It is a standalone bring-up
	harness: point it at a running ledger (e.g. the e2e stack's Davidson log)
	and it seeds the officer delegations, files cases, and (by default) drives
	each case through the full attorney lifecycle to a judge's final_judgment.

	The population is deterministic in -seed: a re-run provisions the same
	people onto the same DIDs and the same dockets.

USAGE:

	scenario -ledger-url https://localhost:8080 -ca-cert .run/<id>/certs/ca.crt \
	         -token baseproof-mode-a -cases 100

	Reads are open; writes present the Mode-A credit token as a bearer. Against
	an ungated dev ledger pass -token "".

KEY DEPENDENCIES:
  - scenario (registry, seeder, generators, live submitter/reader)
  - delegation (BuildContext, cosigned submit pipeline)
  - deployments/tn/trial (the role catalog the seeder's chain derives from)
*/
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/tooling/libs/auth/identity"

	"github.com/clearcompass-ai/judicial-network/delegation"
	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/scenario"
)

// defaultSeed is the deterministic master seed used when -seed is unset. Any
// bytes work (deriveScalar SHA-256-expands them); a stable default makes a bare
// run reproducible across machines.
const defaultSeed = "judicial-network/scenario/davidson/v1"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "scenario: "+err.Error())
		os.Exit(1)
	}
}

func run() error {
	ledgerURL := flag.String("ledger-url", "https://localhost:8080", "ledger base URL")
	caCert := flag.String("ca-cert", "", "PEM CA file pinning the ledger's self-signed server cert (e2e: .run/<id>/certs/ca.crt)")
	insecure := flag.Bool("insecure", false, "skip TLS verification (dev only; prefer -ca-cert)")
	token := flag.String("token", "baseproof-mode-a", "Mode-A credit bearer token; pass \"\" for an ungated/PoW-free dev ledger")
	nCases := flag.Int("cases", 100, "number of cases to file")
	seedStr := flag.String("seed", defaultSeed, "master seed for the deterministic population")
	lifecycle := flag.Bool("lifecycle", true, "file the full attorney lifecycle (counsel_appearance + responsive_pleading) and final_judgment per case")
	timeout := flag.Duration("timeout", 120*time.Second, "per-entry submit+sequence wait budget")
	flag.Parse()

	client, err := newClient(*caCert, *insecure, *timeout)
	if err != nil {
		return err
	}

	// Davidson is the only jurisdiction wired today; the model is data, so a
	// future -jurisdiction flag selects others with no code change.
	j := scenario.DavidsonCounty()
	reg := scenario.BuildRegistry(j, []byte(*seedStr))
	sp := identity.NewStubProvider()
	reg.BindKeys(sp) // bind every principal's derived key so the provider can sign on their behalf

	submitter := scenario.NewHTTPLedgerSubmitter(*ledgerURL, j.ExchangeDID, *token, client, *timeout)
	reader := scenario.NewLedgerReader(*ledgerURL, client)
	bc := &delegation.BuildContext{
		Identity:         sp,
		Submitter:        submitter,
		Catalog:          trial.MustRoleCatalog(),
		ExchangeDID:      j.ExchangeDID,
		InstitutionalDID: j.InstitutionalDID,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if reader.Healthy(ctx) {
		fmt.Printf("ledger %s is healthy\n", *ledgerURL)
	} else {
		fmt.Printf("warning: %s/healthz did not return \"ok\" — submits may fail\n", *ledgerURL)
	}
	fmt.Printf("provisioning %s onto %s: cases=%d lifecycle=%v\n", j.Name, j.ExchangeDID, *nCases, *lifecycle)

	rep, perr := scenario.Provision(ctx, bc, reg, reader, scenario.ProvisionOptions{
		Cases:      *nCases,
		MasterSeed: []byte(*seedStr),
		Lifecycle:  *lifecycle,
	})
	printReport(rep)
	if perr != nil {
		return perr
	}
	fmt.Println("done.")
	return nil
}

// newClient builds the HTTP client the submitter + reader share: the SDK's
// 503/Retry-After-aware client, with TLS pinned to the run CA (-ca-cert),
// skipped (-insecure), or system defaults (plain http:// or public CA).
func newClient(caCertPath string, insecure bool, timeout time.Duration) (*http.Client, error) {
	var tlsCfg *tls.Config
	switch {
	case insecure:
		tlsCfg = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // dev-only opt-in
	case caCertPath != "":
		pem, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read -ca-cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("-ca-cert %s: no PEM certificates found", caCertPath)
		}
		tlsCfg = &tls.Config{RootCAs: pool} //nolint:gosec // pins the run CA
	}
	return sdklog.DefaultClient(timeout, tlsCfg), nil
}

// printReport summarizes what landed on the log.
func printReport(rep *scenario.ProvisionReport) {
	if rep == nil {
		return
	}
	fmt.Printf("seeded %d officer delegations\n", len(rep.Grants))
	var inits, appearances, pleadings, judgments int
	for _, c := range rep.Cases {
		inits++
		if c.CounselAppearance != nil {
			appearances++
		}
		if c.ResponsivePleading != nil {
			pleadings++
		}
		if c.FinalJudgment != nil {
			judgments++
		}
	}
	fmt.Printf("submitted: case_initiation=%d counsel_appearance=%d responsive_pleading=%d final_judgment=%d\n",
		inits, appearances, pleadings, judgments)
	if rep.HeadSize > 0 {
		fmt.Printf("ledger head: tree_size=%d cosignatures=%d\n", rep.HeadSize, rep.HeadSigs)
	}
}
