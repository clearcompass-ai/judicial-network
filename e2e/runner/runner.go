// Package runner executes recipes against a PERSISTED baseproof e2e stack: it
// resolves the live stack from the run store, runs the selected recipes against it
// (without bringing anything up or tearing it down), and reports pass/fail. This is
// what makes `e2e up … && e2e run … && e2e run … && e2e wipe` a real loop.
package runner

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/clearcompass-ai/judicial-network/e2e/runstore"
	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

// Session is the resolved, live stack a recipe runs against.
type Session struct {
	Manifest *runstore.Manifest
	Layout   *runstore.Layout
	Images   stack.Images
}

// Target builds a workload/audit target for a network by name; "" selects the
// first network (the common single-network case).
func (s *Session) Target(networkName string) (stack.Target, bool) {
	single := len(s.Manifest.Networks) == 1
	for _, n := range s.Manifest.Networks {
		if networkName != "" && n.Name != networkName {
			continue
		}
		fx := s.Layout.Fixtures
		if !single {
			fx = filepath.Join(s.Layout.Fixtures, n.Name)
		}
		return stack.Target{
			Network: s.Manifest.Network, LedgerName: n.LedgerName, LedgerPort: n.LedgerPort,
			LogDID: n.LogDID, QuorumK: n.QuorumK, FixturesDir: fx, CertsDir: s.Layout.Certs, Admission: s.Manifest.Admission,
		}, true
	}
	return stack.Target{}, false
}

// Recipe is one named, tagged check run against the session.
type Recipe struct {
	Name string
	Tags []string
	Run  func(s *Session) error
}

var registry = map[string]Recipe{}

// Register adds a recipe to the registry (called from recipe init()).
func Register(r Recipe) { registry[r.Name] = r }

// Names returns the registered recipe names, sorted.
func Names() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Select filters recipes by name substring and/or tag overlap. Empty filters match
// everything.
func Select(names, tags []string) []Recipe {
	out := make([]Recipe, 0, len(registry))
	for _, n := range Names() {
		r := registry[n]
		if len(names) > 0 && !matchesAny(r.Name, names) {
			continue
		}
		if len(tags) > 0 && !overlaps(r.Tags, tags) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func matchesAny(name string, filters []string) bool {
	for _, f := range filters {
		if strings.Contains(name, f) {
			return true
		}
	}
	return false
}

func overlaps(have, want []string) bool {
	set := make(map[string]bool, len(have))
	for _, t := range have {
		set[t] = true
	}
	for _, t := range want {
		if set[t] {
			return true
		}
	}
	return false
}

// Run resolves the persisted stack for runID (or the latest) and runs the selected
// recipes against it. Returns a non-nil error iff any recipe failed.
func Run(runID string, names, tags []string) error {
	id, err := runstore.ResolveID(runID, runstore.Root(), true)
	if err != nil {
		return err
	}
	lay, err := runstore.New(id)
	if err != nil {
		return err
	}
	m, err := lay.LoadManifest()
	if err != nil {
		return fmt.Errorf("no persisted stack for run %s — `e2e up` first", id)
	}
	sess := &Session{Manifest: m, Layout: lay, Images: stack.ResolveImages()}

	selected := Select(names, tags)
	if len(selected) == 0 {
		return fmt.Errorf("no recipes matched (known: %s)", strings.Join(Names(), ", "))
	}

	pass, fail := 0, 0
	for _, r := range selected {
		fmt.Printf("\n== RECIPE %s  [%s] ==\n", r.Name, strings.Join(r.Tags, ", "))
		if err := r.Run(sess); err != nil {
			fmt.Printf("  ✗ FAIL  %s: %v\n", r.Name, err)
			fail++
			continue
		}
		fmt.Printf("  ✔ PASS  %s\n", r.Name)
		pass++
	}
	fmt.Printf("\n  %d passed, %d failed (run %s)\n", pass, fail, id)
	if fail > 0 {
		return fmt.Errorf("%d recipe(s) failed", fail)
	}
	return nil
}
