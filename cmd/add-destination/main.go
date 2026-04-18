// cmd/add-destination/main.go
// Inserts Destination field into every builder.Build* composite literal.
// Uses AST to find call sites, then does line-based insertion.
//
// Usage: go run cmd/add-destination/main.go [--dry-run] [--dest-test VALUE] [--dest-src VALUE]
package main

import (
	"bufio"
	"flag"
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

type site struct {
	file       string
	line       int // line of the builder.BuildXxx( call
	builder    string
	firstField int    // line number of the first field in the composite literal
	indent     string // whitespace before the first field
	isTest     bool
}

func main() {
	dryRun := flag.Bool("dry-run", false, "Print changes without writing")
	destTest := flag.String("dest-test", `"did:web:exchange.test"`, "Destination value for test files")
	destSrc := flag.String("dest-src", "cfg.Destination", "Destination value for source files")
	flag.Parse()

	root := "."
	if flag.NArg() > 0 {
		root = flag.Arg(0)
	}

	// Phase 1: AST scan to find all call sites.
	fset := token.NewFileSet()
	var sites []site
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
		file, e := parser.ParseFile(fset, path, nil, 0)
		if e != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		isTest := strings.HasSuffix(d.Name(), "_test.go")

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

			s := site{
				file:    rel,
				line:    fset.Position(call.Pos()).Line,
				builder: sel.Sel.Name,
				isTest:  isTest,
			}

			// Find the composite literal's first field.
			if len(call.Args) >= 1 {
				if cl, ok := call.Args[0].(*ast.CompositeLit); ok {
					if len(cl.Elts) > 0 {
						firstPos := fset.Position(cl.Elts[0].Pos())
						s.firstField = firstPos.Line
						// Compute indent from the column.
						s.indent = strings.Repeat("\t", (firstPos.Column-1)/4)
						if (firstPos.Column-1)%4 != 0 {
							s.indent = strings.Repeat(" ", firstPos.Column-1)
						}
					}
				}
			}

			sites = append(sites, s)
			return true
		})
		return nil
	})

	// Sort by file, then by line DESCENDING so we can insert from bottom
	// to top without shifting line numbers.
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].file != sites[j].file {
			return sites[i].file < sites[j].file
		}
		return sites[i].firstField > sites[j].firstField // descending
	})

	// Phase 2: Group by file and apply insertions.
	byFile := map[string][]site{}
	for _, s := range sites {
		byFile[s.file] = append(byFile[s.file], s)
	}

	totalPatched := 0
	fileNames := make([]string, 0, len(byFile))
	for f := range byFile {
		fileNames = append(fileNames, f)
	}
	sort.Strings(fileNames)

	for _, fname := range fileNames {
		fileSites := byFile[fname]

		// Read original file.
		lines, err := readLines(filepath.Join(root, fname))
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR reading %s: %v\n", fname, err)
			continue
		}

		patched := 0
		for _, s := range fileSites {
			if s.firstField == 0 {
				fmt.Fprintf(os.Stderr, "SKIP %s:%d %s — no composite literal found\n", fname, s.line, s.builder)
				continue
			}

			// Check if Destination already present (scan the composite literal).
			alreadyHas := false
			for scanLine := s.line; scanLine < len(lines) && scanLine < s.firstField+20; scanLine++ {
				if strings.Contains(lines[scanLine], "Destination:") {
					alreadyHas = true
					break
				}
				if strings.Contains(lines[scanLine], "})") || strings.Contains(lines[scanLine], "})") {
					break
				}
			}
			if alreadyHas {
				continue
			}

			// Determine destination value.
			destValue := *destSrc
			if s.isTest {
				destValue = *destTest
			}

			// Compute indent from the actual first field line.
			idx := s.firstField - 1 // 0-indexed
			if idx >= 0 && idx < len(lines) {
				actualLine := lines[idx]
				trimmed := strings.TrimLeft(actualLine, " \t")
				actualIndent := actualLine[:len(actualLine)-len(trimmed)]
				s.indent = actualIndent
			}

			// Insert Destination line BEFORE the first field.
			insertLine := fmt.Sprintf("%sDestination: %s,", s.indent, destValue)
			insertIdx := s.firstField - 1 // insert before this 0-indexed line

			if insertIdx >= 0 && insertIdx <= len(lines) {
				newLines := make([]string, 0, len(lines)+1)
				newLines = append(newLines, lines[:insertIdx]...)
				newLines = append(newLines, insertLine)
				newLines = append(newLines, lines[insertIdx:]...)
				lines = newLines
				patched++

				// Shift all remaining sites in this file that are below this insertion.
				for j := range fileSites {
					if fileSites[j].firstField > 0 && fileSites[j].firstField >= s.firstField && &fileSites[j] != &s {
						// Already processed (descending order), but for safety:
					}
				}
			}
		}

		if patched > 0 {
			if *dryRun {
				fmt.Printf("[DRY-RUN] %s: would patch %d sites\n", fname, patched)
			} else {
				if err := writeLines(filepath.Join(root, fname), lines); err != nil {
					fmt.Fprintf(os.Stderr, "ERROR writing %s: %v\n", fname, err)
				} else {
					fmt.Printf("PATCHED %s: %d sites\n", fname, patched)
				}
			}
			totalPatched += patched
		}
	}

	fmt.Printf("\nTotal: %d sites patched across %d files\n", totalPatched, len(byFile))
	if *dryRun {
		fmt.Println("(dry-run mode — no files modified)")
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for i, line := range lines {
		w.WriteString(line)
		if i < len(lines)-1 {
			w.WriteByte('\n')
		}
	}
	w.WriteByte('\n')
	return w.Flush()
}
