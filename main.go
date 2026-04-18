// destination_patch analyzes the judicial-network codebase via AST to find
// every builder.Build* call site and generate exact patches for adding the
// Destination field.
//
// Usage: go run main.go /path/to/judicial-network
package main

import (
	"encoding/json"
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

// CallSite records one builder.Build* invocation.
type CallSite struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Builder    string `json:"builder"`     // e.g. "BuildRootEntity"
	ParamsType string `json:"params"`      // e.g. "RootEntityParams"
	FirstField string `json:"first_field"` // e.g. "SignerDID"
	IsTest     bool   `json:"is_test"`
	FuncName   string `json:"in_func"` // enclosing function
}

// buildersRequiringDestination lists every Build* function whose params
// struct now requires a Destination field (from SDK entry_builders.go).
var buildersRequiringDestination = map[string]string{
	"BuildRootEntity":      "RootEntityParams",
	"BuildAmendment":       "AmendmentParams",
	"BuildDelegation":      "DelegationParams",
	"BuildSuccession":      "SuccessionParams",
	"BuildRevocation":      "RevocationParams",
	"BuildScopeCreation":   "ScopeCreationParams",
	"BuildScopeAmendment":  "ScopeAmendmentParams",
	"BuildScopeRemoval":    "ScopeRemovalParams",
	"BuildEnforcement":     "EnforcementParams",
	"BuildCommentary":      "CommentaryParams",
	"BuildCosignature":     "CosignatureParams",
	"BuildRecoveryRequest": "RecoveryRequestParams",
	"BuildAnchorEntry":     "AnchorParams",
	"BuildKeyRotation":     "KeyRotationParams",
	"BuildKeyPrecommit":    "KeyPrecommitParams",
	"BuildSchemaEntry":     "SchemaEntryParams",
	"BuildPathBEntry":      "PathBParams",
	"BuildMirrorEntry":     "MirrorParams",
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	abs, _ := filepath.Abs(root)
	fmt.Fprintf(os.Stderr, "Scanning: %s\n", abs)

	var sites []CallSite
	fset := token.NewFileSet()

	skip := map[string]bool{".git": true, "vendor": true, "node_modules": true}

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

		file, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "WARN: parse %s: %v\n", path, parseErr)
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		isTest := strings.HasSuffix(d.Name(), "_test.go")

		// Track enclosing function name.
		var enclosingFunc string

		ast.Inspect(file, func(n ast.Node) bool {
			// Track enclosing function.
			if fd, ok := n.(*ast.FuncDecl); ok {
				enclosingFunc = fd.Name.Name
				if fd.Recv != nil && len(fd.Recv.List) > 0 {
					recvType := exprStr(fd.Recv.List[0].Type)
					enclosingFunc = "(" + recvType + ")." + fd.Name.Name
				}
			}

			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			// Match builder.BuildXxx or just BuildXxx.
			funcName := ""
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				if id, ok := fn.X.(*ast.Ident); ok && id.Name == "builder" {
					funcName = fn.Sel.Name
				}
			case *ast.Ident:
				funcName = fn.Name
			}

			if funcName == "" {
				return true
			}
			paramsType, tracked := buildersRequiringDestination[funcName]
			if !tracked {
				return true
			}

			// Found a tracked call. Extract the composite literal.
			site := CallSite{
				File:       rel,
				Line:       fset.Position(call.Pos()).Line,
				Builder:    funcName,
				ParamsType: paramsType,
				IsTest:     isTest,
				FuncName:   enclosingFunc,
			}

			// Find the first argument — should be a composite literal.
			if len(call.Args) >= 1 {
				if cl, ok := call.Args[0].(*ast.CompositeLit); ok {
					if len(cl.Elts) > 0 {
						if kv, ok := cl.Elts[0].(*ast.KeyValueExpr); ok {
							site.FirstField = exprStr(kv.Key)
						}
					}
				}
			}

			sites = append(sites, site)
			return true
		})

		return nil
	})

	// Sort by file then line.
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})

	// ─── Output: Summary ────────────────────────────────────────────
	fmt.Printf("# Destination-Binding Patch Report\n\n")
	fmt.Printf("Total call sites found: %d\n\n", len(sites))

	// Group by file.
	byFile := map[string][]CallSite{}
	for _, s := range sites {
		byFile[s.File] = append(byFile[s.File], s)
	}

	// Stats.
	sourceCount := 0
	testCount := 0
	for _, s := range sites {
		if s.IsTest {
			testCount++
		} else {
			sourceCount++
		}
	}
	fmt.Printf("Source files: %d call sites\n", sourceCount)
	fmt.Printf("Test files:   %d call sites\n\n", testCount)

	// ─── Per-builder breakdown ──────────────────────────────────────
	byBuilder := map[string]int{}
	for _, s := range sites {
		byBuilder[s.Builder]++
	}
	fmt.Printf("## Call sites by builder function\n\n")
	builderNames := make([]string, 0, len(byBuilder))
	for b := range byBuilder {
		builderNames = append(builderNames, b)
	}
	sort.Strings(builderNames)
	for _, b := range builderNames {
		fmt.Printf("  %-25s %3d\n", b, byBuilder[b])
	}
	fmt.Println()

	// ─── Per-file listing ───────────────────────────────────────────
	fileNames := make([]string, 0, len(byFile))
	for f := range byFile {
		fileNames = append(fileNames, f)
	}
	sort.Strings(fileNames)

	fmt.Printf("## Per-file call sites\n\n")
	for _, f := range fileNames {
		fileSites := byFile[f]
		tag := "SRC"
		if fileSites[0].IsTest {
			tag = "TEST"
		}
		fmt.Printf("### %s [%s] (%d sites)\n", f, tag, len(fileSites))
		for _, s := range fileSites {
			fmt.Printf("  L%-4d %-25s first_field=%-15s in=%s\n",
				s.Line, s.Builder, s.FirstField, s.FuncName)
		}
		fmt.Println()
	}

	// ─── Generate sed commands ──────────────────────────────────────
	fmt.Printf("## sed commands\n\n")
	fmt.Printf("# For SOURCE files: Destination references a config variable.\n")
	fmt.Printf("# The actual variable name depends on the file's config pattern.\n")
	fmt.Printf("# For TEST files: uses a constant \"did:web:exchange.test\".\n")
	fmt.Printf("# Review each command before running.\n\n")

	for _, f := range fileNames {
		fileSites := byFile[f]
		fmt.Printf("# --- %s (%d sites) ---\n", f, len(fileSites))

		for _, s := range fileSites {
			if s.FirstField == "" {
				fmt.Printf("# SKIP L%d %s — no composite literal found (manual review)\n", s.Line, s.Builder)
				continue
			}

			// The sed pattern: find the line with the params struct opening
			// and the first field, insert Destination before it.
			//
			// Pattern: after "builder.XxxParams{" find the line with FirstField
			// and insert Destination above it.
			destValue := `cfg.Destination`
			if s.IsTest {
				destValue = `"did:web:exchange.test"`
			}

			// We target the first field line (e.g. "SignerDID:") and prepend Destination.
			// Using sed with line address from AST.
			firstFieldLine := s.Line + 1 // First field is typically the line after the call
			if s.FirstField != "" {
				fmt.Printf("sed -n '%dp' %s  # verify: should contain %s\n",
					firstFieldLine, f, s.FirstField)
				fmt.Printf("sed -i '' '%d s/^\\([ \\t]*\\)%s:/\\1Destination: %s,\\n\\1%s:/' %s\n",
					firstFieldLine, s.FirstField, destValue, s.FirstField, f)
			}
		}
		fmt.Println()
	}

	// ─── JSON output for programmatic consumption ───────────────────
	jsonFile := "/tmp/destination_patch_sites.json"
	jf, err := os.Create(jsonFile)
	if err == nil {
		enc := json.NewEncoder(jf)
		enc.SetIndent("", "  ")
		enc.Encode(sites)
		jf.Close()
		fmt.Fprintf(os.Stderr, "\nJSON output: %s\n", jsonFile)
	}

	fmt.Fprintf(os.Stderr, "Done: %d call sites across %d files\n", len(sites), len(byFile))
}

func exprStr(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprStr(x.X) + "." + x.Sel.Name
	case *ast.StarExpr:
		return "*" + exprStr(x.X)
	default:
		return "?"
	}
}
