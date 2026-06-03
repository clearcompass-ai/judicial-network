// Command e2e is the single entrypoint for the baseproof end-to-end stack.
//
// Stack topology is data (see e2e/topology), so any shape is reachable without new
// code: a named preset, or ad-hoc --networks/--witnesses/--auditors/--k flags. A
// stack is brought up once and PERSISTED; tests run against the live stack and can
// be run repeatedly; `wipe` tears it down.
//
//	e2e up <preset> | --networks N --witnesses M --auditors K --k Q
//	e2e list                        list stack presets
//	e2e status                      show the persisted stack
//	e2e run [selectors]             run tests against the persisted stack
//	e2e wipe                        tear down + drop state
//
// Bring-up (the run-store + docker builder + runner) is layered in behind this CLI;
// `up`/`list` resolve and validate topology today, the rest report pending.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/clearcompass-ai/judicial-network/e2e/topology"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "up":
		err = cmdUp(args)
	case "list":
		err = cmdList(args)
	case "status":
		err = cmdStatus(args)
	case "run":
		err = cmdRun(args)
	case "wipe", "down":
		err = cmdWipe(args)
	case "-h", "--help", "help":
		usage(os.Stdout)
		return
	default:
		fmt.Fprintf(os.Stderr, "e2e: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `e2e — baseproof end-to-end stack

usage:
  e2e up <preset | --networks N --witnesses M --auditors K --k Q>
                          bring up + persist a stack
  e2e list                list stack presets
  e2e status              show the persisted stack
  e2e run [selectors]     run tests against the persisted stack
  e2e wipe                tear down + drop state

presets: %s
`, strings.Join(topology.Names(), ", "))
}

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	var (
		networks  = fs.Int("networks", 0, "ad-hoc: number of identical networks (overrides the preset)")
		witnesses = fs.Int("witnesses", 3, "ad-hoc: witnesses per network")
		auditors  = fs.Int("auditors", 2, "ad-hoc: auditors per network")
		quorumK   = fs.Int("k", 2, "ad-hoc: witness quorum K per network")
		admission = fs.String("admission", "", "override tuning: credits|pow")
		proof     = fs.String("proof", "", "override tuning: tiles|pg|shadow")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	var (
		spec topology.StackSpec
		err  error
	)
	if *networks > 0 {
		spec, err = topology.FromFlags(*networks, *witnesses, *auditors, *quorumK)
	} else {
		name := "single"
		if fs.NArg() > 0 {
			name = fs.Arg(0)
		}
		spec, err = topology.Get(name)
	}
	if err != nil {
		return err
	}
	if *admission != "" {
		spec.Tuning.Admission = *admission
	}
	if *proof != "" {
		spec.Tuning.ProofSource = *proof
	}

	printPlan(spec)
	fmt.Println()
	fmt.Println("topology resolved + validated. Bring-up engine (run-store + docker builder)" +
		" is the next layer; it will realise this plan and persist it under .run/{id}.")
	return nil
}

func printPlan(s topology.StackSpec) {
	fmt.Printf("stack %q — %d network(s), %d witnesses, %d auditors  [admission=%s proof=%s]\n",
		s.Name, s.NetworkCount(), s.TotalWitnesses(), s.TotalAuditors(),
		s.Tuning.Admission, s.Tuning.ProofSource)
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "  network\tK\twitnesses\tauditors\tjn\taggregator\tdestinations")
	for _, n := range s.Networks {
		fmt.Fprintf(w, "  %s\t%d\t%d\t%d\t%v\t%v\t%d\n",
			n.Name, n.QuorumK, n.Witnesses, n.Auditors, n.HasJN, n.HasAggregator, len(n.Destinations))
	}
	_ = w.Flush()
	if s.SharedWitnesses > 0 || s.SharedAuditors > 0 {
		fmt.Printf("  shared identities across all networks: %d witness(es), %d auditor(s)\n",
			s.SharedWitnesses, s.SharedAuditors)
	}
}

func cmdList([]string) error {
	for _, n := range topology.Names() {
		s, err := topology.Get(n)
		if err != nil {
			return err
		}
		fmt.Printf("  %-12s %s\n", n, s.Summary())
	}
	return nil
}

func cmdStatus([]string) error { return pending("status") }
func cmdRun([]string) error    { return pending("run") }
func cmdWipe([]string) error   { return pending("wipe") }

func pending(name string) error {
	return fmt.Errorf("%s: pending the stack engine (run-store + docker builder + runner) — the next layer", name)
}
