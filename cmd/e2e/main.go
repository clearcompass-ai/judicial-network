// Command e2e is the single entrypoint for the baseproof end-to-end stack.
//
// Stack topology is data (see e2e/topology), so any shape is reachable without new
// code: a named preset, or ad-hoc --networks/--witnesses/--auditors/--k flags. A
// stack is brought up once and PERSISTED under .run/{id}; tests run against the
// live stack and can be run repeatedly; `wipe` tears it down.
//
//	e2e up <preset> | --networks N --witnesses M --auditors K --k Q [--plan]
//	e2e list                        list stack presets
//	e2e status [--id ID] [--watch 5s]  stack health; --watch = live across-the-stack poll
//	e2e run [selectors]             run tests against the persisted stack
//	e2e wipe [--id ID]              tear down + drop state
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

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
  e2e status [--id ID] [--watch 5s]
                          stack health; --watch polls committed/cosigned/reader/backlog
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

// setDefaultEnv sets k=v only when k is unset, so an explicit env var still wins
// over a flag-driven default (e.g. `up --debug`, `run --scales`).
func setDefaultEnv(k, v string) {
	if os.Getenv(k) == "" {
		_ = os.Setenv(k, v)
	}
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
		debug     = fs.Bool("debug", false, "forensics preset: tail-GC prune + audit + ledger pprof on :6060 (for verify.tiling / heap dumps)")
		trace     = fs.Bool("trace", false, "leaf-loss validation preset (v0.1.4+): per-batch commit-integrity + tile-miss classification")
	)
	preset, err := parseUpArgs(fs, args)
	if err != nil {
		return err
	}
	if *debug {
		// Flip on the validation/forensics knobs the ledger reads at boot, so
		// `up federation --debug` replaces the manual env triplet. setDefaultEnv
		// only sets unset keys, so an explicit E2E_LEDGER_* still wins.
		setDefaultEnv("E2E_LEDGER_TAIL_GC_PRUNE", "1")
		setDefaultEnv("E2E_LEDGER_TAIL_GC_AUDIT", "1")
		setDefaultEnv("E2E_LEDGER_PPROF_ADDR", ":6060")
		fmt.Println("  --debug: tail-GC prune + audit ON; ledger pprof on :6060 (docker exec <ledger> wget -qO- http://localhost:6060/debug/pprof/heap)")
	}
	if *trace {
		// Leaf-loss validation preset (v0.1.4+). The node-index fix is default-ON in
		// the image; this turns on the SIGNALS that prove it in a soak: the per-batch
		// commit-integrity check (names any leaf-loss source node + seq at commit
		// time, O(delta)) and the tile-miss classifier (INTERIOR_TOP_SKIP — fixed by
		// the index — vs STRANDED_TOP). A clean run = 0 commit-integrity flags.
		setDefaultEnv("E2E_LEDGER_TRACE_COMMIT", "1")
		setDefaultEnv("E2E_LEDGER_TILE_VERIFY_FETCH", "1")
		fmt.Println("  --trace: leaf-loss validation ON — per-batch commit-integrity + tile-miss classify " +
			"(grep the ledger logs for LEDGER_TRACE_COMMIT integrity flags / 'BUILDER NODE MISS' verdicts)")
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

// jnImageBuild describes one JN-owned image built from the local working tree.
type jnImageBuild struct {
	label       string // human label
	dockerfile  string // repo-relative Dockerfile path
	image       string // the tag to build (the resolved Images.* ref)
	envOverride string // the E2E_*_IMAGE that, when set, pins a prebuilt image instead
}

// ensureImages provisions every container image the stack needs. The JN-owned
// images (the network-api enforcer + the aggregator) are BUILT from the local
// working tree so the e2e exercises the code under test — the published ghcr image
// routinely lags the branch (e.g. the open-HTTPS JN→ledger leg), which is exactly
// why the e2e must not depend on it. The tooling fleet (ledger/witness/auditor)
// and infra (postgres/seaweed) are PULLED (published, versioned dependencies). An
// operator can pin a prebuilt JN image via E2E_JN_IMAGE / E2E_AGGREGATOR_IMAGE
// (then it is pulled/used as-is rather than built); E2E_SKIP_BUILD / E2E_SKIP_PULL
// skip either phase.
func ensureImages() error {
	im := stack.ResolveImages()

	// 1. Build the JN-owned images from source (unless pinned via env).
	if os.Getenv("E2E_SKIP_BUILD") != "1" {
		root, err := repoRoot()
		if err != nil {
			return err
		}
		version := jnVersion(root)
		secrets := caBundleSecret()
		builds := []jnImageBuild{
			{"network-api (JN enforcer)", "deployment/local/Dockerfile.network-api", im.JN, "E2E_JN_IMAGE"},
			{"aggregator (read projection)", "deployment/local/Dockerfile.aggregator", im.Aggregator, "E2E_AGGREGATOR_IMAGE"},
		}
		header := false
		for _, b := range builds {
			if os.Getenv(b.envOverride) != "" {
				continue // operator pinned a prebuilt image — pulled below
			}
			if !header {
				fmt.Println("== build JN images (local working tree) ==")
				header = true
			}
			fmt.Printf("  building %-28s → %s\n", b.label, b.image)
			if err := dockerx.Build(dockerx.BuildSpec{
				Tag:        b.image,
				Dockerfile: filepath.Join(root, b.dockerfile),
				Context:    root,
				BuildArgs:  map[string]string{"VERSION": version},
				Secrets:    secrets,
			}); err != nil {
				return fmt.Errorf("docker build %s (-f %s): %w", b.label, b.dockerfile, err)
			}
			fmt.Printf("  ✔ built %s\n", b.image)
		}
	}

	// 2. Pull infra + the tooling fleet (+ any operator-pinned JN images).
	if os.Getenv("E2E_SKIP_PULL") == "1" {
		return nil
	}
	fmt.Println("== pull images ==")
	for _, img := range pullList(im) {
		if r := dockerx.Pull(img); !r.OK() {
			return fmt.Errorf("docker pull %s failed — `docker login ghcr.io` (read:packages) and confirm the tag is published:\n%s",
				img, strings.TrimSpace(r.Stderr))
		}
		fmt.Printf("  ✔ %s\n", img)
	}
	return nil
}

// pullList is the set of images to PULL: infra + the tooling fleet always, plus a
// JN-owned image ONLY when the operator pinned it via E2E_*_IMAGE (otherwise it is
// built locally, not pulled, so a stale ghcr image can never shadow the build).
func pullList(im stack.Images) []string {
	out := []string{im.Postgres, im.Seaweed, im.Ledger, im.Witness, im.Auditor}
	if os.Getenv("E2E_JN_IMAGE") != "" {
		out = append(out, im.JN)
	}
	if os.Getenv("E2E_AGGREGATOR_IMAGE") != "" {
		out = append(out, im.Aggregator)
	}
	return out
}

// repoRoot locates the JN repo root (the docker build context): the nearest
// ancestor of the cwd that holds BOTH go.mod and the JN Dockerfiles. Overridable
// via E2E_REPO_ROOT.
func repoRoot() (string, error) {
	if r := os.Getenv("E2E_REPO_ROOT"); r != "" {
		return filepath.Abs(r)
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for dir := wd; ; {
		_, goErr := os.Stat(filepath.Join(dir, "go.mod"))
		_, dfErr := os.Stat(filepath.Join(dir, "deployment", "local", "Dockerfile.network-api"))
		if goErr == nil && dfErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find the JN repo root above %s (need go.mod + deployment/local/Dockerfile.network-api) — run from the repo, or set E2E_REPO_ROOT", wd)
		}
		dir = parent
	}
}

// jnVersion stamps main.Version into the built binaries: the git describe of the
// working tree (so a soak's logs identify the exact code), or "dev" outside git.
func jnVersion(root string) string {
	out, err := exec.Command("git", "-C", root, "describe", "--tags", "--always", "--dirty").Output()
	if err != nil {
		return "dev"
	}
	return strings.TrimSpace(string(out))
}

// caBundleSecret passes the host CA bundle as the ca_bundle build secret when
// present, so module/package fetches verify behind a TLS-inspecting egress proxy
// (the CI sandbox / corporate-net case). A no-op when absent (the Dockerfiles
// guard on an empty secret). Overridable via E2E_CA_BUNDLE.
func caBundleSecret() []string {
	p := os.Getenv("E2E_CA_BUNDLE")
	if p == "" {
		p = "/etc/ssl/certs/ca-certificates.crt"
	}
	if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
		return []string{"id=ca_bundle,src=" + p}
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
		fmt.Fprintf(w, "  %s\thttps://localhost:%d\t%s\n", n.Name, n.LedgerPort, jn)
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
	watch := fs.Duration("watch", 0, "poll the stack every interval (e.g. 5s); 0 = one-shot snapshot")
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

	if *watch <= 0 {
		renderStackStatus(m, lay, nil, time.Time{})
		return nil
	}

	// Watch mode: a recipe-independent, across-the-stack progress poll. Run it in a
	// SECOND terminal while any recipe drives load — it shows, per network, whether
	// work is PROPAGATING: committed head (builder) + its delta, the cosigned horizon
	// (witnesses) it lags, the reader's horizon (cold-serve parity), and the WAL
	// backlog (shipping). Ctrl-C to stop.
	fmt.Printf("watching stack %q every %s — committed=builder, cosigned=witnesses, reader=cold front; Ctrl-C to stop\n",
		m.ID, *watch)
	start := time.Now()
	prev := map[string]headSample{}
	for {
		prev = renderStackStatus(m, lay, prev, start)
		time.Sleep(*watch)
	}
}

// headSample is one tick's per-network heads, kept so the next tick can show deltas.
type headSample struct{ committed, cosigned int }

// renderStackStatus draws one across-the-stack snapshot and returns this tick's heads
// (for the next tick's deltas). prev==nil / start==zero ⇒ the one-shot snapshot.
func renderStackStatus(m *runstore.Manifest, lay *runstore.Layout, prev map[string]headSample, start time.Time) map[string]headSample {
	if start.IsZero() {
		fmt.Printf("stack %q (preset %s, network %s)\n", m.ID, m.Preset, m.Network)
	} else {
		fmt.Printf("\n── %s  run %s  (elapsed %s) ─────────────────────────────────────\n",
			time.Now().Format("15:04:05"), m.ID, time.Since(start).Round(time.Second))
	}
	now := make(map[string]headSample, len(m.Networks))
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "  net\thealth\tcommitted\tcosigned\tlag\treader\tbacklog\tstate")
	for _, n := range m.Networks {
		health := "down"
		if stack.LedgerHealthy(n, lay.Certs) {
			health = "ok"
		}
		committed, _ := stack.HeadStatus(lay.Certs, n.LedgerPort)
		cosigned := horizonSize(lay.Certs, n.LedgerPort)
		now[n.Name] = headSample{committed: committed, cosigned: cosigned}

		dc, delta, haveDelta := "", 0, false
		if p, ok := prev[n.Name]; ok {
			delta, haveDelta = committed-p.committed, true
			dc = fmt.Sprintf(" (%+d)", delta)
		}
		reader := "-"
		if n.ReaderPort != 0 {
			reader = sizeOrDash(horizonSize(lay.Certs, n.ReaderPort))
		}
		backlog := backlogOrDash(lay.Certs, n.LedgerPort)
		fmt.Fprintf(w, "  %s\t%s\t%d%s\t%s\t%d\t%s\t%s\t%s\n",
			n.Name, health, committed, dc, sizeOrDash(cosigned), committed-cosigned, reader, backlog,
			stackState(health, committed, cosigned, delta, haveDelta, backlog))
	}
	_ = w.Flush()
	return now
}

// horizonSize is the cosigned horizon tree_size at a port, 0 when unavailable
// (pre-genesis 503 / unreachable).
func horizonSize(certsDir string, port int) int {
	hz, err := stack.FetchHorizon(certsDir, port)
	if err != nil {
		return 0
	}
	return hz.TreeSize
}

func sizeOrDash(n int) string {
	if n <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d", n)
}

func backlogOrDash(certsDir string, port int) string {
	if v, ok := stack.WALBacklog(certsDir, port); ok {
		return fmt.Sprintf("%d", v)
	}
	return "-"
}

// stackState classifies a network's propagation from the live signals — the one-word
// answer to "what is happening here": DOWN, committing (builder advancing), cosigning
// (committed done, witnesses catching up), shipping (backlog draining), STALLED
// (committed behind + not advancing + backlog), or caught-up.
func stackState(health string, committed, cosigned, delta int, haveDelta bool, backlog string) string {
	if health != "ok" {
		return "DOWN"
	}
	if haveDelta && delta > 0 {
		return "committing"
	}
	pending := backlog != "0" && backlog != "-"
	if committed > cosigned {
		if haveDelta && delta == 0 && pending {
			return "STALLED?" // committed behind cosign, not advancing, work pending
		}
		return "cosigning"
	}
	if pending {
		return "shipping"
	}
	return "caught-up"
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

// parseInterleaved parses fs allowing flags to appear BEFORE or AFTER positional
// args, returning the positionals in order. Go's flag package stops at the first
// non-flag token, so a bare fs.Parse silently drops flags written after a positional
// (e.g. `run verify.tiling --scales N`). This parses flags, consumes one positional,
// and repeats until none remain.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for rest := args; ; {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		rest = rest[1:]
	}
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var (
		id     = fs.String("id", "", "run id (default: latest)")
		name   = fs.String("name", "", "recipe name filter (substring)")
		tag    = fs.String("tag", "", "recipe tag filter")
		list   = fs.Bool("list", false, "list recipes and exit")
		scales = fs.String("scales", "", `verify.tiling: cumulative entry-count ladder, e.g. "200000 500000 1000000 2000000"`)
		mode   = fs.String("mode", "", "verify.tiling: deep|quick")
		cpuSec = fs.Int("cpu-seconds", -1, "verify.tiling: CPU profile seconds per 1% snapshot (0 disables)")
	)
	// Accept flags whether they appear BEFORE or AFTER the positional recipe names.
	// Go's flag package stops at the first non-flag arg, so a bare fs.Parse(args)
	// silently DROPS flags written after a recipe name (e.g.
	// `run verify.tiling --scales 20000` would ignore --scales and fall back to the
	// default). Interleave: parse flags, take one positional, repeat.
	names, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if *list {
		for _, n := range runner.Names() {
			fmt.Printf("  %s\n", n)
		}
		return nil
	}
	// Recipe flags are sugar over the recipe's env knobs (so an explicit env still
	// wins if a flag is left unset). verify.tiling reads E2E_VALIDATE_*.
	if *scales != "" {
		_ = os.Setenv("E2E_VALIDATE_SCALES", *scales)
	}
	if *mode != "" {
		_ = os.Setenv("E2E_VALIDATE_MODE", *mode)
	}
	if *cpuSec >= 0 {
		_ = os.Setenv("E2E_VALIDATE_CPU_SECONDS", fmt.Sprint(*cpuSec))
	}
	var tags []string
	if *name != "" {
		names = append(names, *name)
	}
	if *tag != "" {
		tags = append(tags, *tag)
	}
	return runner.Run(*id, names, tags)
}
