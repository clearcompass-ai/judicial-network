/*
FILE PATH: verification/liveness_census_test.go

DESCRIPTION:

	The cross-engine LIVENESS census guard (PRE-13a). This is the
	default-on test that ends the rollback loop: it makes the
	revoked-judge false-negative structurally unconstructible by
	pinning, in CI, the one rule that was previously enforced only by
	a doc comment.

	THE RULE (single owner): delegation/authority liveness is
	`leaf.OriginTip == position` ∧ not-expired, owned by
	tooling/libs/auth/authority.SMTChainResolver. verifier.EvaluateOrigin
	is for ENTITY/CASE-root state ONLY — it classifies a self-targeting
	delegation revocation as Amended⇒live (the false negative that
	produced the original bug), so it must never compute delegation
	liveness.

	Two guards:
	  - TestCensus_EvaluateOriginConfinedToEntityState: verifier.EvaluateOrigin
	    may appear ONLY in the entity/case-state allowlist. A NEW engine that
	    calls it on a delegation/authority path fails CI here.
	  - TestLock_NoLegacyAuthorityWalkRegrows: the retired JN-local
	    AuthorityResolver (which carried the stale EvaluateOrigin liveness) must
	    not reappear — a re-declared `type AuthorityResolver` fails CI here. With
	    the tooling-home pin (authority/home_pin_test.go, which refuses the
	    verifier import at the canonical resolver) this is the cross-layer
	    false-green guard.
*/
package verification

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// evaluateOriginAllowlist is the CLOSED set of files permitted to call
// verifier.EvaluateOrigin (entity/case-root state — the correct job).
// Keys are module-root-relative, slash-separated.
var evaluateOriginAllowlist = map[string]string{
	"api/verification/handlers/verify_batch.go":  "entity/origin-state verify API",
	"api/verification/handlers/verify_origin.go": "origin-state verify API",
	"cases/artifact/retrieve.go":                 "entity-state access check",
	"cases/docket_query.go":                      "case-state docket lookup",
	"verification/case_status.go":                "case-state",
}

func jnModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from the test directory")
		}
		dir = parent
	}
}

func walkProdGoFiles(t *testing.T, root string, visit func(rel string, f *ast.File, fset *token.FileSet)) {
	t.Helper()
	fset := token.NewFileSet()
	skip := map[string]bool{".git": true, "vendor": true, "testdata": true, "node_modules": true}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skip[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		visit(filepath.ToSlash(rel), f, fset)
		return nil
	})
}

// TestCensus_EvaluateOriginConfinedToEntityState fails if verifier.EvaluateOrigin
// is called anywhere outside the entity/case-state allowlist. This is the
// cross-engine guard the PRE-13 rollback loop lacked.
func TestCensus_EvaluateOriginConfinedToEntityState(t *testing.T) {
	root := jnModuleRoot(t)
	walkProdGoFiles(t, root, func(rel string, f *ast.File, fset *token.FileSet) {
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "EvaluateOrigin" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "verifier" {
				return true
			}
			if _, allowed := evaluateOriginAllowlist[rel]; !allowed {
				t.Errorf("%s: verifier.EvaluateOrigin is forbidden here — it classifies entity/case-root "+
					"state and reads a self-targeting delegation revocation as live. Delegation liveness MUST "+
					"use OriginTip==position (libs/auth/authority.SMTChainResolver). If this is a genuine "+
					"entity-state reader, add it to evaluateOriginAllowlist with a justification.", rel)
			}
			return true
		})
	})
}

// TestLock_NoLegacyAuthorityWalkRegrows is the JN-side regrowth guard: the
// retired JN-local AuthorityResolver (which derived liveness from the stale
// verifier.EvaluateOrigin — the revoked-judge false negative) must not reappear.
// A re-declared `type AuthorityResolver` in production fails CI here. The gate's
// only authority engine is SMTAuthorityResolver over tooling/libs/auth/authority
// (OriginTip==position); its companion tooling-home pin (home_pin_test.go)
// refuses the verifier import. Together they are the cross-layer false-green
// guard the rollback loop lacked.
func TestLock_NoLegacyAuthorityWalkRegrows(t *testing.T) {
	root := jnModuleRoot(t)
	walkProdGoFiles(t, root, func(rel string, f *ast.File, fset *token.FileSet) {
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			if ts.Name.Name == "AuthorityResolver" {
				t.Errorf("%s: re-declares type AuthorityResolver — the JN-local delegation walk was "+
					"retired (it carried the EvaluateOrigin revoked-judge false negative). The gate uses "+
					"SMTAuthorityResolver (OriginTip==position). Do not regrow a domain-local walk.", rel)
			}
			return true
		})
	})
}
