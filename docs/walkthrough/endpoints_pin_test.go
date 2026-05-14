/*
FILE PATH: docs/walkthrough/endpoints_pin_test.go

DESCRIPTION:

	Pins the set of JN domain-API endpoints that the walkthrough's
	evidence curls depend on. If a route is renamed or removed in
	api/judicial/*.go, this test surfaces the breakage at CI time
	with a pointer to which walkthrough step depends on it.

	Citations_pin_test.go pins schema struct/serializer line
	numbers. This test pins API contracts — specifically, the
	HTTP routes whose existence the walkthrough explicitly relies
	on via curl examples.

	Scope: the routes are listed explicitly (not parsed from
	markdown) because (a) we want stable failures with an
	actionable message rather than fuzzy text matching, and (b) the
	walkthrough's curl examples sometimes elide path parameters
	(/v1/judicial/cases/2024-CV-001 vs the registered pattern
	/v1/judicial/cases/{docket}) and a naive regex would surface
	false negatives.

	Failure mode: when a route is broken, the test prints which
	walkthrough step depends on it, so the author updating the API
	knows where to update the doc.
*/
package walkthrough_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// walkthroughEndpoint is one route the walkthrough evidence curls
// rely on. The handler-file substring is the file:fragment we
// expect to see `mux.Handle("<method-and-path>", ...)` in.
type walkthroughEndpoint struct {
	// methodPath is the literal first argument to mux.Handle. Must
	// match byte-for-byte.
	methodPath string
	// handlerFile is the file under api/judicial/ where the
	// handler is registered. Used for the failure message; we
	// grep the file for methodPath to confirm.
	handlerFile string
	// walkthroughCite is the walkthrough step where this route is
	// the evidence-curl target. Helps the API author find the doc
	// to update.
	walkthroughCite string
}

// pinnedEndpoints is the load-bearing contract this test enforces.
// Every entry corresponds to an evidence-curl example in
// docs/walkthrough/cases/*.md. Adding a curl that hits a new JN
// endpoint => add the route here.
var pinnedEndpoints = []walkthroughEndpoint{
	{
		methodPath:      "GET /v1/judicial/cases/{docket}",
		handlerFile:     "cases.go",
		walkthroughCite: "01-acme-v-beta-trial.md Step 1, 02-anderson-filing.md Step 1, 02-anderson-succession.md Step 6 (case lookup)",
	},
	{
		methodPath:      "GET /v1/judicial/parties/bindings/by-id/{bindingID}",
		handlerFile:     "parties.go",
		walkthroughCite: "01-acme-v-beta-trial.md Step 2, 02-anderson-filing.md Step 3 (party binding lookup)",
	},
	{
		methodPath:      "GET /v1/judicial/parties/bindings",
		handlerFile:     "parties.go",
		walkthroughCite: "01-acme-v-beta-trial.md Step 3, 02-anderson-filing.md Step 4 (case bindings list)",
	},
	{
		methodPath:      "GET /v1/judicial/verification/custody-chain",
		handlerFile:     "verification.go",
		walkthroughCite: "01-acme-v-beta-trial.md Step 4 (referenced for forensic custody audit)",
	},
	{
		methodPath:      "GET /v1/judicial/verification/background-check",
		handlerFile:     "verification.go",
		walkthroughCite: "future walkthrough extension (party background-check audit)",
	},
	{
		methodPath:      "GET /v1/judicial/verification/case-status",
		handlerFile:     "verification.go",
		walkthroughCite: "future walkthrough extension (case-status snapshot)",
	},
	{
		methodPath:      "GET /v1/judicial/enforcement/sealing-status",
		handlerFile:     "enforcement.go",
		walkthroughCite: "02-anderson-filing.md Step 3 (sealed-binding audit; future expansion)",
	},
}

// TestWalkthroughEndpoints_AllRegistered confirms every endpoint
// the walkthrough's evidence curls rely on is still registered in
// api/judicial/<handlerFile>.
//
// Failure surface example:
//
//	FAIL: walkthrough cites GET /v1/judicial/cases/{docket}
//	      (registration expected in api/judicial/cases.go)
//	      but no such mux.Handle line found.
//	      Walkthrough steps that will break: 01-acme-v-beta-trial.md Step 1, ...
//
// Fix path: either restore the route in cases.go, or update the
// walkthrough step + this test's pinnedEndpoints to reflect the
// new endpoint name.
func TestWalkthroughEndpoints_AllRegistered(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(cwd, "..", ".."))

	for _, ep := range pinnedEndpoints {
		ep := ep
		t.Run(strings.ReplaceAll(ep.methodPath, "/", "_"), func(t *testing.T) {
			path := filepath.Join(repoRoot, "api", "judicial", ep.handlerFile)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("walkthrough cites %s in %s but the handler file is missing: %v\nWalkthrough steps that will break: %s",
					ep.methodPath, ep.handlerFile, err, ep.walkthroughCite)
				return
			}
			needle := `mux.Handle("` + ep.methodPath + `"`
			if !strings.Contains(string(content), needle) {
				t.Errorf("walkthrough cites %s (expected mux.Handle registration in api/judicial/%s) but the literal %q was not found.\nWalkthrough steps that will break: %s\nFix: either restore the route in %s or update the walkthrough step + pinnedEndpoints in this test.",
					ep.methodPath, ep.handlerFile, needle, ep.walkthroughCite, ep.handlerFile)
			}
		})
	}
}

// TestWalkthroughEndpoints_NoDuplicates ensures the pinnedEndpoints
// list itself is free of accidental duplication — a duplicate would
// hide a real route deletion behind a still-passing entry for a
// different walkthrough step.
func TestWalkthroughEndpoints_NoDuplicates(t *testing.T) {
	seen := make(map[string]string, len(pinnedEndpoints))
	for _, ep := range pinnedEndpoints {
		if prev, ok := seen[ep.methodPath]; ok {
			t.Errorf("pinnedEndpoints has duplicate entry for %s (first cite: %q, second: %q)",
				ep.methodPath, prev, ep.walkthroughCite)
		}
		seen[ep.methodPath] = ep.walkthroughCite
	}
}
