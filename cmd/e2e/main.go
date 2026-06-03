// Command e2e is the single entrypoint for the baseproof end-to-end stack.
//
// Stack topology is data (see e2e/topology), so any shape is reachable without new
// code: a named preset, or ad-hoc --networks/--witnesses/--auditors/--k flags. A
// stack is brought up once and PERSISTED under .run/{id}; tests run against the
// live stack and can be run repeatedly; `wipe` tears it down.
//
//	e2e up <preset> | --networks N --witnesses M --auditors K --k Q [--plan]
//	e2e list                        list stack presets
//	e2e status [--id ID]            show the persisted stack + health
//	e2e run [selectors]             run tests against the persisted stack
//	e2e wipe [--id ID]              tear down + drop state
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/clearcompass-ai/judicial-network/e2e/dockerx"
	"github.com/clearcompass-ai/judicial-network/e2e/runner"
	"github.com/clearcompass-ai/judicial-network/e2e/runstore"
	"github.com/clearcompass-ai/judicial-network/e2e/stack"
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
  e2e up <preset | --networks N --witnesses M --auditors K --k Q> [--plan] [--id ID]
                          bring up + persist a stack
  e2e list                list stack presets
  e2e status [--id ID]    show the persisted stack + health
  e2e run [selectors]     run tests against the persisted stack
  e2e wipe [--id ID]      tear down + drop state

presets: %s
`, strings.Join(topology.Names(), ", "))
}

func resolveSpec(preset string, networks, witnesses, auditors, quorumK int, admission, proof string) (topology.StackSpec, error) {
	var (
		spec topology.StackSpec
		err  error
	)
	if networks > 0 {
		spec, err = topology.FromFlags(networks, witnesses, auditors, quorumK)
	} else {
		if preset == "" {
			preset = "single"
		}
		spec, err = topology.Get(preset)
	}
	if err != nil {
		return spec, err
	}
	if admission != "" {
		spec.Tuning.Admission = admission
	}
	if proof != "" {
		spec.Tuning.ProofSource = proof
	}
	return spec, nil
}

// parseUpArgs parses the up flag set tolerating the preset positional appearing
// before OR after flags (Go's flag package stops at the first positional, so we
// re-parse what follows the preset). Returns the preset (may be "").
func parseUpArgs(fs *flag.FlagSet, args []string) (string, error) {
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	rest := fs.Args()
	if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
		return "", nil
	}
	preset := rest[0]
	if err := fs.Parse(rest[1:]); err != nil {
		return "", err
	}
	return preset, nil
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
		id        = fs.String("id", "", "reuse a specific 3-char run id (default: a fresh id)")
		planOnly  = fs.Bool("plan", false, "resolve + print the topology plan without bringing anything up")
	)
	preset, err := parseUpArgs(fs, args)
	if err != nil {
		return err
	}
	spec, err := resolveSpec(preset, *networks, *witnesses, *auditors, *quorumK, *admission, *proof)
	if err != nil {
		return err
	}
	printPlan(spec)
	if *planOnly {
		return nil
	}
	if !dockerx.DaemonOK() {
		return fmt.Errorf("docker daemon not reachable")
	}
	runID, err := runstore.ResolveID(*id, runstore.Root(), false)
	if err != nil {
		return err
	}
	if err := ensureImages(); err != nil {
		return err
	}
	m, err := stack.Build(spec, runID)
	if err != nil {
		return err
	}
	printManifest(m)
	return nil
}

func ensureImages() error {
	if os.Getenv("E2E_SKIP_PULL") == "1" {
		return nil
	}
	fmt.Println("== pull images ==")
	for _, img := range stack.ResolveImages().All() {
		if r := dockerx.Pull(img); !r.OK() {
			return fmt.Errorf("docker pull %s failed — `docker login ghcr.io` (read:packages) and confirm the tag is published:\n%s",
				img, strings.TrimSpace(r.Stderr))
		}
		fmt.Printf("  ✔ %s\n", img)
	}
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

func printManifest(m *runstore.Manifest) {
	fmt.Printf("\n== STACK UP — persisted as run %s ==\n", m.ID)
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "  network\tledger\tjn")
	for _, n := range m.Networks {
		jn := "-"
		if n.JNPort != 0 {
			jn = fmt.Sprintf("https://localhost:%d", n.JNPort)
		}
		fmt.Fprintf(w, "  %s\thttp://localhost:%d\t%s\n", n.Name, n.LedgerPort, jn)
	}
	_ = w.Flush()
	fmt.Printf("  run tests : e2e run [selectors]   (reuses this stack)\n")
	fmt.Printf("  inspect   : e2e status --id %s\n", m.ID)
	fmt.Printf("  wipe      : e2e wipe --id %s\n", m.ID)
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

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	id := fs.String("id", "", "run id (default: latest)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	runID, err := runstore.ResolveID(*id, runstore.Root(), true)
	if err != nil {
		return err
	}
	lay, err := runstore.New(runID)
	if err != nil {
		return err
	}
	m, err := lay.LoadManifest()
	if err != nil {
		return fmt.Errorf("no persisted stack for run %s — bring one up first", runID)
	}
	fmt.Printf("stack %q (preset %s, network %s)\n", m.ID, m.Preset, m.Network)
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "  network\tledger\thealth\tquorum")
	for _, n := range m.Networks {
		health := "down"
		if stack.LedgerHealthy(n) {
			health = "ok"
		}
		fmt.Fprintf(w, "  %s\thttp://localhost:%d\t%s\tK=%d\n", n.Name, n.LedgerPort, health, n.QuorumK)
	}
	_ = w.Flush()
	return nil
}

func cmdWipe(args []string) error {
	fs := flag.NewFlagSet("wipe", flag.ContinueOnError)
	id := fs.String("id", "", "run id (default: latest)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	runID, err := runstore.ResolveID(*id, runstore.Root(), true)
	if err != nil {
		return err
	}
	if err := stack.Wipe(runID); err != nil {
		return err
	}
	fmt.Printf("wiped run %s (containers + state)\n", runID)
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var (
		id   = fs.String("id", "", "run id (default: latest)")
		name = fs.String("name", "", "recipe name filter (substring)")
		tag  = fs.String("tag", "", "recipe tag filter")
		list = fs.Bool("list", false, "list recipes and exit")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *list {
		for _, n := range runner.Names() {
			fmt.Printf("  %s\n", n)
		}
		return nil
	}
	var names, tags []string
	if *name != "" {
		names = append(names, *name)
	}
	if *tag != "" {
		tags = append(tags, *tag)
	}
	// positional recipe names (e.g. `e2e run audit.tiles`).
	names = append(names, fs.Args()...)
	return runner.Run(*id, names, tags)
}
