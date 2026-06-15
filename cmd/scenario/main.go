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
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"time"

	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/tooling/libs/auth/identity"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

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
	institutionalKey := flag.String("institutional-key", "", "KeyFile JSON whose private key signs depth-0 grants AS the institutional DID (the run's genesis key from `init-network -out-ledger-key`); empty uses the derived key")
	identitiesDir := flag.String("identities-dir", "", "if set, write each principal's KeyFile (institutional, judges, clerks, attorneys) into this directory")
	provision := flag.Bool("provision", true, "seed officers + file cases (set false to only export identities and/or verify an existing ledger)")
	verify := flag.Bool("verify", false, "after provisioning, read every case back as a blind consumer (public reads only) and validate completeness")
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

	// Seam: on a live stack the institutional did:web root is the genesis
	// identity whose key the ledger trusts — not the derived key. Bind the run's
	// genesis key so depth-0 grants verify.
	if *institutionalKey != "" {
		if err := bindKeyFile(sp, j.InstitutionalDID, *institutionalKey); err != nil {
			return err
		}
		fmt.Printf("institutional signer %s bound to key from %s\n", j.InstitutionalDID, *institutionalKey)
	}

	reader := scenario.NewLedgerReader(*ledgerURL, client)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Export identities (independent of provisioning): materialize every
	// principal's keypair so they are real, inspectable, reusable on disk.
	if *identitiesDir != "" {
		n, eerr := reg.ExportIdentities(*identitiesDir)
		if eerr != nil {
			return eerr
		}
		fmt.Printf("wrote %d identities to %s\n", n, *identitiesDir)
	}

	var provisioned int
	if *provision {
		if reader.Healthy(ctx) {
			fmt.Printf("ledger %s is healthy\n", *ledgerURL)
		} else {
			fmt.Printf("warning: %s/healthz did not return \"ok\" — submits may fail\n", *ledgerURL)
		}
		bc := &delegation.BuildContext{
			Identity:         sp,
			Submitter:        scenario.NewHTTPLedgerSubmitter(*ledgerURL, j.ExchangeDID, *token, client, *timeout),
			Catalog:          trial.MustRoleCatalog(),
			ExchangeDID:      j.ExchangeDID,
			InstitutionalDID: j.InstitutionalDID,
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
		provisioned = len(rep.Cases)
	}

	// Blind-consumer read-back: reconstruct + validate the cases from public
	// reads alone, trusting nothing from the provisioning side.
	if *verify {
		fmt.Printf("verifying %s as a blind consumer (public reads only)...\n", j.ExchangeDID)
		audit, aerr := scenario.AuditLedger(ctx, *ledgerURL, j.ExchangeDID, client)
		if aerr != nil {
			return fmt.Errorf("verify: %w", aerr)
		}
		printAudit(audit)
		if *provision && *lifecycle && len(audit.Complete) < provisioned {
			return fmt.Errorf("verify FAILED: provisioned %d cases but only %d read back with the full lifecycle",
				provisioned, len(audit.Complete))
		}
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

// bindKeyFile loads a repo-standard KeyFile JSON (the format judicial-cli keygen
// and the ledger's signer both write) and binds its secp256k1 private key to did
// in the provider, so entries signed AS did use that key.
func bindKeyFile(sp *identity.StubProvider, did, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read -institutional-key: %w", err)
	}
	var kf struct {
		PrivateKeyHex string `json:"private_key_hex"`
	}
	if err := json.Unmarshal(data, &kf); err != nil {
		return fmt.Errorf("parse -institutional-key %s: %w", path, err)
	}
	b, err := hex.DecodeString(kf.PrivateKeyHex)
	if err != nil {
		return fmt.Errorf("-institutional-key %s: bad private_key_hex: %w", path, err)
	}
	if len(b) != 32 {
		return fmt.Errorf("-institutional-key %s: private_key_hex must be 32 bytes, got %d", path, len(b))
	}
	sp.BindKey(did, secp256k1.PrivKeyFromBytes(b))
	return nil
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

// printAudit summarizes the blind-consumer read-back.
func printAudit(a *scenario.LedgerAuditReport) {
	if a == nil {
		return
	}
	fmt.Printf("blind read: tree_size=%d decoded=%d cases=%d complete=%d incomplete=%d\n",
		a.TreeSize, a.Decoded, len(a.Cases), len(a.Complete), len(a.Incomplete))
	keys := make([]string, 0, len(a.EventCounts))
	for k := range a.EventCounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, et := range keys {
		fmt.Printf("  %-24s %d\n", et, a.EventCounts[et])
	}
	if len(a.Incomplete) > 0 {
		show := a.Incomplete
		if len(show) > 10 {
			show = show[:10]
		}
		fmt.Printf("  incomplete dockets (first %d of %d): %v\n", len(show), len(a.Incomplete), show)
	}
}
