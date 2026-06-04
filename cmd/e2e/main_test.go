package main

import (
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
