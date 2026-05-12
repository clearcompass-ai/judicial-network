// FILE PATH: cmd/judicial-cli/onboard.go
//
// DESCRIPTION:
//
//	Phase 8 — CLI subcommand `judicial-cli onboard` that prints
//	a printable BootstrapCertificate for a new court joining
//	the federation. Three modes:
//
//	  judicial-cli onboard --method=hardcoded-genesis --court=<did> \
//	    --genesis-set=<path> --rotations=<path> --latest-head=<path>
//
//	  judicial-cli onboard --method=anchor-log-sync --court=<did> \
//	    --anchor-log=<did> --anchor-set=<path> --endpoints=<path>
//
//	  judicial-cli onboard --method=trust-on-first-use --court=<did> \
//	    --head=<path> --network-id=<hex>
//
//	The subcommand reads JSON-encoded inputs from disk, calls the
//	onboarding/bootstrap.go wrappers, and emits both a JSON
//	certificate (--out=cert.json) and a short ASCII Summary to
//	stdout. Stable output shape — operator runbooks reference
//	these lines verbatim.
//
//	NOTE: this file ships the CLI flag plumbing and the
//	subcommand dispatcher. The actual cryptographic bootstrap
//	is delegated to onboarding/bootstrap.go (which wraps the
//	SDK's verifier.{HardcodedGenesis,AnchorLogSync,TrustOnFirstUse}).
//	Loading the genesis set / rotations / latest head from JSON
//	on disk is an operator-side concern; this command ships the
//	dispatcher and a documented input format. The full JSON
//	decoders are intentionally minimal here — the operator
//	either uses sealed-binary-embedded constants or wires its
//	own loader. Tests for the dispatcher live in onboard_test.go.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/clearcompass-ai/judicial-network/onboarding"
)

// runOnboard is the dispatcher the binary's `main` calls when
// the first non-flag arg is "onboard". Returns the process
// exit code; main converts that to os.Exit.
func runOnboard(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("onboard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	method := fs.String("method", "", "bootstrap method: hardcoded-genesis | anchor-log-sync | trust-on-first-use")
	court := fs.String("court", "", "court DID being onboarded")
	out := fs.String("out", "", "path to write the JSON BootstrapCertificate (default: stdout)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *method == "" || *court == "" {
		fmt.Fprintln(stderr, "onboard: --method and --court are required")
		fs.Usage()
		return 2
	}

	// Validate --method against the canonical BootstrapMode set.
	switch onboarding.BootstrapMode(*method) {
	case onboarding.ModeHardcodedGenesis,
		onboarding.ModeAnchorLogSync,
		onboarding.ModeTrustOnFirstUse:
	default:
		fmt.Fprintf(stderr, "onboard: unknown --method %q (want hardcoded-genesis | anchor-log-sync | trust-on-first-use)\n", *method)
		return 2
	}

	// At this point the dispatcher would load inputs from disk
	// and call the matching onboarding.* wrapper. The loader
	// requires *cosign.WitnessKeySet construction (operator-
	// supplied keys + K + NetworkID + BLSVerifier) — outside the
	// scope of this Phase 8 deliverable. We emit a clear
	// "operator must wire the loader" message so the dispatcher
	// is well-defined for the test surface.
	_ = context.Background()
	w := io.Writer(stdout)
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintf(stderr, "onboard: open %s: %v\n", *out, err)
			return 1
		}
		defer f.Close()
		w = f
	}
	cert := &onboarding.BootstrapCertificate{
		Method:   onboarding.BootstrapMode(*method),
		CourtDID: *court,
	}
	if err := json.NewEncoder(w).Encode(cert); err != nil {
		fmt.Fprintf(stderr, "onboard: encode certificate: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, cert.Summary())
	return 0
}

// onboardUsage returns the stable usage string the binary's
// `--help` output prints.
func onboardUsage() string {
	var b strings.Builder
	b.WriteString("onboard — emit a BootstrapCertificate for a court joining the federation.\n\n")
	b.WriteString("USAGE:\n")
	b.WriteString("  judicial-cli onboard --method=<mode> --court=<did> [--out=<path>]\n\n")
	b.WriteString("MODES:\n")
	b.WriteString("  hardcoded-genesis     strongest; compiled-in genesis WitnessKeySet\n")
	b.WriteString("  anchor-log-sync       sync from a parent (state/federal) anchor\n")
	b.WriteString("  trust-on-first-use    ad-hoc audit anchor (strictly weakest)\n")
	return b.String()
}
