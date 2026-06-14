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
	  - TestLock_AuthorityResolverNotWiredToGate: the demoted AuthorityResolver
	    still carries the stale EvaluateOrigin liveness; its caveat ("port
	    liveness before wiring to any gate") is enforced here, not by a comment —
	    no PRODUCTION code may construct it.
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

	// DEMOTED delegation engine. Allowed ONLY because
	// TestLock_AuthorityResolverNotWiredToGate proves it cannot reach a
	// production gate (the live gate uses SMTAuthorityResolver / OriginTip==
	// position). Delete this entry — and the engine — when the action-authz
	// path is removed.
	"verification/authority_resolver_origin.go": "demoted, off-gate (see lock test)",
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

// TestLock_AuthorityResolverNotWiredToGate enforces the AuthorityResolver
// caveat with a test rather than a comment: no production code may construct
// the demoted engine (it carries the stale EvaluateOrigin liveness). The engine's
// own definition files are exempt (they declare it; they do not wire it).
func TestLock_AuthorityResolverNotWiredToGate(t *testing.T) {
	root := jnModuleRoot(t)
	walkProdGoFiles(t, root, func(rel string, f *ast.File, fset *token.FileSet) {
		if strings.HasPrefix(rel, "verification/authority_resolver") {
			return // the engine's own files
		}
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			name := ""
			switch tt := cl.Type.(type) {
			case *ast.Ident:
				name = tt.Name
			case *ast.SelectorExpr:
				name = tt.Sel.Name
			}
			if name == "AuthorityResolver" {
				t.Errorf("%s: constructs AuthorityResolver in production — it carries the stale "+
					"EvaluateOrigin liveness (revoked-judge false negative). The gate must use "+
					"SMTAuthorityResolver (OriginTip==position). Port its liveness before wiring it.", rel)
			}
			return true
		})
	})
}
