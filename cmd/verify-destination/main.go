// cmd/verify-destination/main.go
// Verifies every builder.Build* call site has a Destination field.
// Run: go run cmd/verify-destination/main.go
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var tracked = map[string]bool{
	"BuildRootEntity": true, "BuildAmendment": true, "BuildDelegation": true,
	"BuildSuccession": true, "BuildRevocation": true, "BuildScopeCreation": true,
	"BuildScopeAmendment": true, "BuildScopeRemoval": true, "BuildEnforcement": true,
	"BuildCommentary": true, "BuildCosignature": true, "BuildRecoveryRequest": true,
	"BuildAnchorEntry": true, "BuildKeyRotation": true, "BuildKeyPrecommit": true,
	"BuildSchemaEntry": true, "BuildPathBEntry": true, "BuildMirrorEntry": true,
}

type finding struct {
	file    string
	line    int
	builder string
	hasDest bool
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	fset := token.NewFileSet()
	var findings []finding
	skip := map[string]bool{".git": true, "vendor": true}

	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		file, e := parser.ParseFile(fset, path, nil, 0)
		if e != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != "builder" {
				return true
			}
			if !tracked[sel.Sel.Name] {
				return true
			}

			f := finding{
				file:    rel,
				line:    fset.Position(call.Pos()).Line,
				builder: sel.Sel.Name,
			}

			// Check if the composite literal has a Destination field.
			if len(call.Args) >= 1 {
				if cl, ok := call.Args[0].(*ast.CompositeLit); ok {
					for _, elt := range cl.Elts {
						if kv, ok := elt.(*ast.KeyValueExpr); ok {
							if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Destination" {
								f.hasDest = true
								break
							}
						}
					}
				}
			}

			findings = append(findings, f)
			return true
		})
		return nil
	})

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].file != findings[j].file {
			return findings[i].file < findings[j].file
		}
		return findings[i].line < findings[j].line
	})

	pass, fail := 0, 0
	for _, f := range findings {
		if f.hasDest {
			pass++
		} else {
			fail++
			fmt.Printf("[MISSING] %s:%d %s\n", f.file, f.line, f.builder)
		}
	}

	fmt.Printf("\n=== Destination Binding Verification ===\n")
	fmt.Printf("Total call sites: %d\n", len(findings))
	fmt.Printf("With Destination: %d\n", pass)
	fmt.Printf("MISSING:          %d\n", fail)

	if fail > 0 {
		fmt.Printf("\n%d call sites need Destination field added.\n", fail)
		os.Exit(1)
	}
	fmt.Println("\nAll call sites have Destination. ✓")
}
