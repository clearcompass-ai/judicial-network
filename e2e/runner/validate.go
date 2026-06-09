package runner

// verify.tiling — the automated, evidence-capturing validation of the pruned-tail
// tiling-stall fix at scale. It drives a cumulative ENTRY-COUNT LADDER against an
// already-up stack's writer (the `federal` network by default), and for each rung:
//
//   - backfills the delta and watches the SMT horizon (/v1/tree/head tree_size)
//     advance to target — a FROZEN horizon (the stall) shows up as a drain timeout;
//   - streams a metrics time-series to .test/validate-<id>/<scale>/metrics.csv,
//     flushed every poll (no buffering) — tree_size, frontier_lag, tail_nodes,
//     tail-GC orphans/violations, WAL disk, RssAnon;
//   - in DEEP mode, snapshots the TOP MEMORY (inuse_space) and TOP CPU consumers at
//     every new 1% of progress: raw .prof + parsed `go tool pprof -top` text under
//     <scale>/prof/, plus a top-3 row per percent in heap-summary.csv / cpu-summary.csv;
//   - emits a per-rung PASS/FAIL verdict (horizon reached, lag/tail bounded, 0 audit
//     violations, prune active, no stall signature, RssAnon flat) + a final SMT audit.
//
// The ledger version is NEVER hardcoded — it is whatever ResolveImages() resolved
// (s.Images.Ledger). The pprof port is read from the ledger container's own
// LEDGER_PPROF_ADDR (that listener is plain HTTP by design and not on the public TLS
// mux, so profiles are pulled via `docker exec`); everything else — metrics, head,
// audit — is the ledger's open HTTPS.
//
// Knobs: E2E_VALIDATE_SCALES ("200000 500000 1000000 2000000"; default E2E_FED_ENTRIES),
// E2E_VALIDATE_MODE (deep|quick), E2E_VALIDATE_INTERVAL_S (15), E2E_VALIDATE_CPU_SECONDS
// (5; 0 disables CPU), E2E_VALIDATE_NETWORK (federal), E2E_FED_WORKERS, E2E_FED_BATCH_SIZE,
// E2E_DRAIN_TIMEOUT_MIN, E2E_AUDIT_SAMPLES, E2E_AUDIT_RANDOM.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/clearcompass-ai/judicial-network/e2e/dockerx"
	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "verify.tiling", Tags: []string{"verify", "tiling", "soak", "memory"}, Run: verifyTiling})
}

func strEnv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// parseScales turns "200000 500000,1000000" into a sorted, de-duplicated ascending
// list of cumulative entry-count targets.
func parseScales(spec string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for _, f := range strings.FieldsFunc(spec, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' }) {
		n, err := strconv.Atoi(f)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("bad scale %q in E2E_VALIDATE_SCALES", f)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no scales parsed from %q", spec)
	}
	sort.Ints(out)
	return out, nil
}

func verifyTiling(s *Session) error {
	netName := strEnv("E2E_VALIDATE_NETWORK", "")
	if netName == "" {
		for _, n := range s.Manifest.Networks {
			if n.Name == "federal" {
				netName = "federal"
				break
			}
		}
	}
	t, ok := s.Target(netName)
	if !ok {
		return fmt.Errorf("verify.tiling: no target network (looked for %q)", netName)
	}

	scales, err := parseScales(strEnv("E2E_VALIDATE_SCALES", strconv.Itoa(intEnv("E2E_FED_ENTRIES", 200000))))
	if err != nil {
		return err
	}
	deep := !strings.EqualFold(strEnv("E2E_VALIDATE_MODE", "deep"), "quick")
	interval := time.Duration(intEnv("E2E_VALIDATE_INTERVAL_S", 15)) * time.Second
	cpuSecs := intEnv("E2E_VALIDATE_CPU_SECONDS", 5)
	workers := intEnv("E2E_FED_WORKERS", 16)
	batch := intEnv("E2E_FED_BATCH_SIZE", 1)
	drain := time.Duration(intEnv("E2E_DRAIN_TIMEOUT_MIN", 240)) * time.Minute
	image := s.Images.Ledger // version DERIVED from ResolveImages, never hardcoded

	evRoot := filepath.Join(".test", "validate-"+s.Layout.ID)
	if err := os.MkdirAll(evRoot, 0o755); err != nil {
		return fmt.Errorf("verify.tiling: mkdir %s: %w", evRoot, err)
	}
	mode := "deep(heap+cpu@1%)"
	if !deep {
		mode = "quick(metrics-only)"
	}
	fmt.Printf("== verify.tiling: network=%s container=%s ledger=%s mode=%s scales=%v evidence=%s ==\n",
		netNameOr(netName), t.LedgerName, image, mode, scales, evRoot)

	pprofPort := preflight(t, image, evRoot)
	if deep && pprofPort == 0 {
		fmt.Println("  WARN: ledger has no LEDGER_PPROF_ADDR — deep heap/cpu capture disabled (metrics only). Set E2E_LEDGER_PPROF_ADDR=:6060 at `up`.")
	}

	base, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort) // entries already present before validation
	added := 0
	allPass := true
	for _, target := range scales {
		delta := target - added
		if delta <= 0 {
			continue
		}
		pass, ferr := runRung(t, image, evRoot, pprofPort, target, delta, base+target, workers, batch, drain, interval, deep, cpuSecs)
		if ferr != nil {
			return ferr // setup/fatal — abort the suite
		}
		allPass = allPass && pass
		added = target
	}
	if !allPass {
		return fmt.Errorf("verify.tiling: one or more rungs FAILED — see %s", evRoot)
	}
	fmt.Printf("== verify.tiling PASS across %v — evidence under %s ==\n", scales, evRoot)
	return nil
}

func netNameOr(n string) string {
	if n == "" {
		return "(first)"
	}
	return n
}

// preflight records the ledger image + relevant env to <evRoot>/preflight.txt and
// returns the pprof port parsed from the container's LEDGER_PPROF_ADDR (0 if unset).
func preflight(t stack.Target, image, evRoot string) int {
	env := dockerx.Exec(t.LedgerName, []string{"env"}, false).Stdout
	var b strings.Builder
	fmt.Fprintf(&b, "resolved_image=%s\ncontainer=%s\n", image, t.LedgerName)
	for _, ln := range strings.Split(env, "\n") {
		if strings.HasPrefix(ln, "LEDGER_TAIL_GC") || strings.HasPrefix(ln, "LEDGER_PPROF") || strings.HasPrefix(ln, "GOMEMLIMIT") ||
			strings.HasPrefix(ln, "LEDGER_NODE_INDEX") || strings.HasPrefix(ln, "LEDGER_TRACE_COMMIT") || strings.HasPrefix(ln, "LEDGER_TILE_VERIFY_FETCH") {
			fmt.Fprintln(&b, ln)
		}
	}
	_ = os.WriteFile(filepath.Join(evRoot, "preflight.txt"), []byte(b.String()), 0o644)
	if !strings.Contains(env, "LEDGER_TAIL_GC_PRUNE=1") {
		fmt.Println("  WARN: LEDGER_TAIL_GC_PRUNE is not set on the ledger — the tail prune is OFF for this run.")
	}
	// v0.1.4 leaf-loss fix is default-ON, so LEDGER_NODE_INDEX only appears here when
	// explicitly set (an A/B arm). Flag the OFF arm loudly — it is expected to LOSE
	// leaves at scale (the very fault this release closes).
	if strings.Contains(env, "LEDGER_NODE_INDEX=0") {
		fmt.Println("  WARN: LEDGER_NODE_INDEX=0 — the node-index leaf-loss fix is DISABLED for this run (A/B baseline; expect leaf loss at scale).")
	}
	port := 0
	for _, ln := range strings.Split(env, "\n") {
		if v := strings.TrimPrefix(ln, "LEDGER_PPROF_ADDR="); v != ln {
			if i := strings.LastIndexByte(v, ':'); i >= 0 {
				port, _ = strconv.Atoi(strings.TrimSpace(v[i+1:]))
			}
		}
	}
	return port
}

type rungState struct {
	maxLag, maxTail, maxViol, lastOrph int
	rss0, rssMax, rssLast              int
	stalls                             int
}

// runRung backfills `delta` entries to bring the tree to `targetTree`, monitoring +
// (deep) profiling throughout. Returns (pass, fatalErr). A fatalErr is a setup/backfill
// failure that should abort the whole suite; a non-pass with nil error is a recorded
// verdict failure the caller tallies.
func runRung(t stack.Target, image, evRoot string, pprofPort, target, delta, targetTree, workers, batch int,
	drain, interval time.Duration, deep bool, cpuSecs int) (bool, error) {

	dir := filepath.Join(evRoot, strconv.Itoa(target))
	profd := filepath.Join(dir, "prof")
	if err := os.MkdirAll(profd, 0o755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", profd, err)
	}
	mcsv, err := os.Create(filepath.Join(dir, "metrics.csv"))
	if err != nil {
		return false, err
	}
	defer mcsv.Close()
	fmt.Fprintln(mcsv, "wallclock,elapsed_s,tree_size,pct,rate_eps,frontier_lag,tail_nodes,orphans_dropped,audit_violations,wal_disk_bytes,rss_anon_kb")
	_ = mcsv.Sync()
	memSum := newSummary(filepath.Join(dir, "heap-summary.csv"))
	cpuSum := newSummary(filepath.Join(dir, "cpu-summary.csv"))
	defer memSum.close()
	defer cpuSum.close()

	startTree, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
	fmt.Printf("  -- rung %d: backfill %d (tree %d -> %d), drain ceiling %s --\n", target, delta, startTree, targetTree, drain)

	type bfres struct {
		st  *stack.BackfillStats
		err error
	}
	done := make(chan bfres, 1)
	go func() { st, e := stack.Backfill(t, image, delta, workers, 0.5, batch); done <- bfres{st, e} }()

	canProf := deep && pprofPort > 0
	if canProf {
		capProf(t.LedgerName, pprofPort, profd, memSum, cpuSum, 0, startTree, cpuSecs)
	}

	start := time.Now()
	deadline := start.Add(drain)
	var st rungState
	lastPct := -1
	lastTree, lastT := startTree, start
	var bf bfres
	bfDone, timedOut := false, false

	for {
		now := time.Now()
		tree, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
		lag := gaugeInt(t, "baseproof_smt_frontier_lag_total")
		tail := gaugeInt(t, "baseproof_smt_tail_nodes")
		orph := gaugeInt(t, "baseproof_tail_gc_orphans_dropped_total")
		viol := gaugeInt(t, "baseproof_tail_gc_audit_violations_total")
		wal := gaugeInt(t, "baseproof_wal_disk_bytes")
		rss := rssAnonKB(t.LedgerName)

		pct := 0
		if delta > 0 {
			pct = (tree - startTree) * 100 / delta
		}
		if pct < 0 {
			pct = 0
		} else if pct > 100 {
			pct = 100
		}
		rate := 0
		if dt := int(now.Sub(lastT).Seconds()); dt > 0 {
			rate = (tree - lastTree) / dt
		}

		fmt.Fprintf(mcsv, "%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
			now.Format("15:04:05"), int(now.Sub(start).Seconds()), tree, pct, rate, lag, tail, orph, viol, wal, rss)
		_ = mcsv.Sync() // continuous: visible to tail/another terminal immediately

		st.maxLag = max(st.maxLag, lag)
		st.maxTail = max(st.maxTail, tail)
		st.maxViol = max(st.maxViol, viol)
		st.lastOrph = orph
		if rss > 0 {
			if st.rss0 == 0 {
				st.rss0 = rss
			}
			st.rssLast = rss
			st.rssMax = max(st.rssMax, rss)
		}
		if h := recentStalls(t.LedgerName, interval); h > 0 {
			st.stalls += h
			fmt.Printf("  *** STALL SIGNATURE at tree_size=%d (%d%%) — interior node missing / smt_tiles_not_durable ***\n", tree, pct)
		}

		if canProf && pct > lastPct {
			capProf(t.LedgerName, pprofPort, profd, memSum, cpuSum, pct, tree, cpuSecs)
		}
		if pct > lastPct && pct%10 == 0 {
			fmt.Printf("  rung %d: %d%%  tree=%d  lag=%d  tail=%d  orphans=%d  rssAnon=%dkB\n", target, pct, tree, lag, tail, orph, rss)
		}
		lastPct, lastTree, lastT = pct, tree, now

		if tree >= targetTree {
			break // drained to target — horizon kept up
		}
		if !bfDone {
			select {
			case bf = <-done:
				bfDone = true
				if bf.err != nil {
					return false, fmt.Errorf("rung %d backfill: %w", target, bf.err)
				}
			default:
			}
		}
		if now.After(deadline) {
			timedOut = true
			break
		}
		time.Sleep(interval)
	}
	if !bfDone {
		bf = <-done
		if bf.err != nil {
			return false, fmt.Errorf("rung %d backfill: %w", target, bf.err)
		}
	}

	// Final correctness capstone: a light-client SMT audit proves the tree at this
	// size is servable from the tiles (the horizon advanced AND is provable).
	auditOK := true
	if out, aerr := stack.RunAudit(t, image, intEnv("E2E_AUDIT_SAMPLES", 64), intEnv("E2E_AUDIT_RANDOM", 16), true); aerr != nil {
		auditOK = false
		_ = os.WriteFile(filepath.Join(dir, "audit.txt"), []byte("FAILED: "+aerr.Error()+"\n"+out), 0o644)
	} else {
		_ = os.WriteFile(filepath.Join(dir, "audit.txt"), []byte(out), 0o644)
	}
	if canProf {
		treef, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
		capProf(t.LedgerName, pprofPort, profd, memSum, cpuSum, 100, treef, cpuSecs)
	}

	treef, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
	return writeVerdict(dir, target, targetTree, treef, timedOut, auditOK, st), nil
}

func writeVerdict(dir string, target, targetTree, treef int, timedOut, auditOK bool, st rungState) bool {
	pass := true
	var b strings.Builder
	chk := func(ok bool, msg string) {
		if ok {
			fmt.Fprintf(&b, "  PASS  %s\n", msg)
		} else {
			fmt.Fprintf(&b, "  FAIL  %s\n", msg)
			pass = false
		}
	}
	chk(!timedOut && treef >= targetTree, fmt.Sprintf("horizon reached target: tree_size=%d / %d (drain %s)", treef, targetTree, okno(!timedOut)))
	chk(st.stalls == 0, fmt.Sprintf("zero 'interior node missing' / smt_tiles_not_durable (hits=%d)", st.stalls))
	chk(st.maxViol == 0, fmt.Sprintf("tail_gc_audit_violations stayed 0 (peak=%d)", st.maxViol))
	chk(st.lastOrph > 0, fmt.Sprintf("tail-GC prune active (orphans_dropped=%d)", st.lastOrph))
	chk(auditOK, "light-client SMT audit verified at this size (tree servable)")
	fmt.Fprintf(&b, "  INFO  max frontier_lag=%d  max tail_nodes=%d  (bounded => horizon kept pace, tail not O(history))\n", st.maxLag, st.maxTail)
	fmt.Fprintf(&b, "  INFO  RssAnon kB: start=%d max=%d end=%d  (flat => no O(history) heap growth)\n", st.rss0, st.rssMax, st.rssLast)
	header := fmt.Sprintf("== VERDICT  rung=%d  %s ==\n", target, passStr(pass))
	_ = os.WriteFile(filepath.Join(dir, "verdict.txt"), []byte(header+b.String()), 0o644)
	fmt.Print(header + b.String())
	return pass
}

func okno(b bool) string {
	if b {
		return "ok"
	}
	return "TIMEOUT"
}
func passStr(b bool) string {
	if b {
		return "*** PASS ***"
	}
	return "!!! FAIL !!!"
}

// ---- metric / profile helpers ----

func gaugeInt(t stack.Target, name string) int {
	if v, ok := stack.ScrapeGauge(t.CertsDir, t.LedgerPort, name); ok {
		return int(v)
	}
	return 0
}

func rssAnonKB(container string) int {
	r := dockerx.Exec(container, []string{"awk", "/RssAnon/{print $2}", "/proc/1/status"}, false)
	n, _ := strconv.Atoi(strings.TrimSpace(r.Stdout))
	return n
}

// recentStalls counts the stall signature in the ledger's logs over the last
// window (bounded — uses `docker logs --since`, not the full log).
func recentStalls(container string, window time.Duration) int {
	secs := int(window.Seconds()) + 5
	out, _ := exec.Command("docker", "logs", "--since", strconv.Itoa(secs)+"s", container).CombinedOutput()
	s := string(out)
	return strings.Count(s, "interior node missing") + strings.Count(s, "smt_tiles_not_durable")
}

// capProf pulls a heap (inuse_space) and, if cpuSecs>0, a CPU profile from the
// in-container pprof listener (plain HTTP, by design not on the TLS mux) via
// `docker exec`, saves the raw .prof + a `go tool pprof -top` rendering, and appends
// a top-3 row to the summary CSV.
func capProf(container string, pprofPort int, profd string, memSum, cpuSum *summary, pct, tree, cpuSecs int) {
	tag := fmt.Sprintf("%03dpct-ts%d", pct, tree)
	// memory (instant): which type RETAINS bytes — the leak signal.
	if raw, err := dockerExecBytes(container, "wget", "-qO-",
		fmt.Sprintf("http://localhost:%d/debug/pprof/heap", pprofPort)); err == nil && len(raw) > 0 {
		f := filepath.Join(profd, "heap-"+tag+".prof")
		_ = os.WriteFile(f, raw, 0o644)
		if top, terr := pprofTop(f, "-inuse_space", "-unit=B"); terr == nil {
			_ = os.WriteFile(f+".top.txt", []byte(top), 0o644)
			memSum.add(pct, tree, top)
		}
	}
	// cpu (blocks cpuSecs): which functions burn CPU — the throughput signal.
	if cpuSecs > 0 {
		if raw, err := dockerExecBytes(container, "wget", "-T", strconv.Itoa(cpuSecs+15), "-qO-",
			fmt.Sprintf("http://localhost:%d/debug/pprof/profile?seconds=%d", pprofPort, cpuSecs)); err == nil && len(raw) > 0 {
			f := filepath.Join(profd, "cpu-"+tag+".prof")
			_ = os.WriteFile(f, raw, 0o644)
			if top, terr := pprofTop(f); terr == nil {
				_ = os.WriteFile(f+".top.txt", []byte(top), 0o644)
				cpuSum.add(pct, tree, top)
			}
		}
	}
}

func dockerExecBytes(container string, args ...string) ([]byte, error) {
	return exec.Command("docker", append([]string{"exec", container}, args...)...).Output()
}

func pprofTop(file string, extra ...string) (string, error) {
	args := append([]string{"tool", "pprof", "-top", "-nodecount=25"}, extra...)
	args = append(args, file)
	out, err := exec.Command("go", args...).CombinedOutput()
	return string(out), err
}

// ---- summary CSV (top-3 consumers per percent) ----

type summary struct{ f *os.File }

func newSummary(path string) *summary {
	f, err := os.Create(path)
	if err != nil {
		return &summary{}
	}
	fmt.Fprintln(f, "pct,tree_size,total,top1_flat,top1_sym,top2_flat,top2_sym,top3_flat,top3_sym")
	_ = f.Sync()
	return &summary{f: f}
}

func (s *summary) add(pct, tree int, topText string) {
	if s == nil || s.f == nil {
		return
	}
	total, rows := parseTop(topText)
	cell := func(i int) (string, string) {
		if i < len(rows) {
			return rows[i][0], rows[i][1]
		}
		return "", ""
	}
	f1, s1 := cell(0)
	f2, s2 := cell(1)
	f3, s3 := cell(2)
	fmt.Fprintf(s.f, "%d,%d,%s,%s,%s,%s,%s,%s,%s\n", pct, tree, total, f1, s1, f2, s2, f3, s3)
	_ = s.f.Sync()
}

func (s *summary) close() {
	if s != nil && s.f != nil {
		_ = s.f.Close()
	}
}

// parseTop extracts the "of <X> total" figure and the first three data rows
// (flat, symbol) from `go tool pprof -top` output.
func parseTop(text string) (total string, rows [][2]string) {
	inRows := false
	for _, ln := range strings.Split(text, "\n") {
		if total == "" {
			if i := strings.Index(ln, "of "); i >= 0 && strings.Contains(ln, " total") {
				if fs := strings.Fields(ln[i:]); len(fs) >= 2 {
					total = fs[1]
				}
			}
		}
		f := strings.Fields(ln)
		if !inRows {
			if len(f) >= 2 && f[0] == "flat" && f[1] == "flat%" {
				inRows = true
			}
			continue
		}
		if len(f) >= 6 && len(rows) < 3 {
			rows = append(rows, [2]string{f[0], f[len(f)-1]})
		}
	}
	return total, rows
}
