package main

import (
	"flag"
	"reflect"
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// TestPullList_BuildsJNByDefault pins the contract: the JN-owned images
// (network-api enforcer + aggregator) are BUILT from the working tree, so they are
// NOT in the pull list by default — the tooling fleet + infra are. A stale ghcr JN
// image can never shadow the local build.
func TestPullList_BuildsJNByDefault(t *testing.T) {
	t.Setenv("E2E_JN_IMAGE", "")
	t.Setenv("E2E_AGGREGATOR_IMAGE", "")
	im := stack.Images{
		Postgres: "pg", Seaweed: "sw", Ledger: "led", Witness: "wit", Auditor: "aud",
		JN: "jn", Aggregator: "agg",
	}
	got := pullList(im)
	for _, want := range []string{"pg", "sw", "led", "wit", "aud"} {
		if !contains(got, want) {
			t.Errorf("pullList missing fleet/infra image %q: %v", want, got)
		}
	}
	if contains(got, "jn") || contains(got, "agg") {
		t.Errorf("JN-owned images must be BUILT (not pulled) by default; pullList = %v", got)
	}
}

// TestPullList_PullsPinnedJNImages: an operator pin (E2E_JN_IMAGE) flips that image
// to PULL while an unpinned peer is still built.
func TestPullList_PullsPinnedJNImages(t *testing.T) {
	im := stack.Images{
		Postgres: "pg", Seaweed: "sw", Ledger: "led", Witness: "wit", Auditor: "aud",
		JN: "jn", Aggregator: "agg",
	}
	t.Setenv("E2E_JN_IMAGE", "ghcr.io/clearcompass-ai/judicial-network:pinned")
	t.Setenv("E2E_AGGREGATOR_IMAGE", "")
	got := pullList(im)
	if !contains(got, "jn") {
		t.Errorf("a pinned E2E_JN_IMAGE must be pulled; pullList = %v", got)
	}
	if contains(got, "agg") {
		t.Errorf("an unpinned aggregator must be built, not pulled; pullList = %v", got)
	}
}

// TestParseInterleaved guards `e2e run` arg parsing: flags must be honored whether
// they appear before OR after the positional recipe name. Pins the regression where
// `run verify.tiling --scales 20000` silently dropped --scales (Go's flag stops at
// the first positional) so the recipe fell back to its default scale.
func TestParseInterleaved(t *testing.T) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	scales := fs.String("scales", "", "")
	id := fs.String("id", "", "")
	list := fs.Bool("list", false, "")

	// flags AFTER the positional (the bug case), interleaved between positionals
	pos, err := parseInterleaved(fs, []string{"verify.tiling", "--id", "pl0", "--scales", "20000", "extra", "--list"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *scales != "20000" {
		t.Errorf("--scales after positional not parsed: got %q, want 20000", *scales)
	}
	if *id != "pl0" {
		t.Errorf("--id after positional not parsed: got %q, want pl0", *id)
	}
	if !*list {
		t.Error("--list after positional not parsed")
	}
	if want := []string{"verify.tiling", "extra"}; !reflect.DeepEqual(pos, want) {
		t.Errorf("positionals = %v, want %v", pos, want)
	}

	// flags BEFORE the positional (already worked) still works
	fs2 := flag.NewFlagSet("run", flag.ContinueOnError)
	s2 := fs2.String("scales", "", "")
	pos2, err := parseInterleaved(fs2, []string{"--scales", "500", "verify.tiling"})
	if err != nil {
		t.Fatalf("parse2: %v", err)
	}
	if *s2 != "500" || !reflect.DeepEqual(pos2, []string{"verify.tiling"}) {
		t.Errorf("flags-before broke: scales=%q pos=%v", *s2, pos2)
	}
}
