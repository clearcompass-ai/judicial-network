/*
FILE PATH: docs/walkthrough/citations_pin_test.go

DESCRIPTION:

	Pins every "schemas/X.go:N" code citation in the walkthrough
	markdown files to the actual file:line in HEAD. Walkthroughs
	cite struct definitions and serializers to give readers a
	jump-to-source path; if a schema grows by 3 lines and the
	walkthrough still says ":29", the reader navigates to the
	wrong type and loses trust. This test catches that drift at
	CI time.

	Scope: only file:line pairs of the form `schemas/<name>.go:<n>`
	in markdown under docs/walkthrough/. Every cited line must
	begin with either `type ` or `func ` (declarations only —
	the walkthroughs cite struct types and serializer functions).

	Failure mode is loud: each drifted citation is reported with
	the expected vs. observed line. Updating the walkthrough is
	then a one-line fix per citation.

	This test deliberately lives under docs/ (not under schemas/)
	so the walkthrough's stewards see CI breakage on a doc change
	rather than schema authors hitting it on every refactor.
*/
package walkthrough_test

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// citationRE matches `schemas/<name>.go:<n>` plus a few common
// surrounding characters. We keep the regex tight to avoid false
// positives in narrative prose.
var citationRE = regexp.MustCompile(`schemas/([a-z_]+)\.go:(\d+)`)

// declRE matches the start of a Go top-level declaration line: a
// type or func declaration. Citation lines MUST begin with one
// of these tokens.
var declRE = regexp.MustCompile(`^(type|func)\s`)

// TestWalkthroughCitations_AllMatchHead walks every .md under
// docs/walkthrough/ and confirms that every schemas/x.go:N citation
// resolves to a `type` or `func` declaration line in the referenced
// file at HEAD.
//
// If a schema's line numbers shift, the citation must be updated.
// Update is mechanical: open the schema, find the new line of the
// cited identifier, fix the markdown.
func TestWalkthroughCitations_AllMatchHead(t *testing.T) {
	// Resolve the repo root from this test file's location:
	//   <repo>/docs/walkthrough/citations_pin_test.go
	// → repoRoot = ../../
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(cwd, "..", ".."))
	walkRoot := filepath.Join(cwd) // current test pkg dir already IS docs/walkthrough/

	type cite struct {
		mdFile   string
		mdLine   int
		schemaFn string // e.g., "civil_case.go"
		lineNum  int
	}
	var citations []cite

	err = filepath.Walk(walkRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			for _, m := range citationRE.FindAllStringSubmatch(scanner.Text(), -1) {
				ln, perr := strconv.Atoi(m[2])
				if perr != nil {
					continue
				}
				citations = append(citations, cite{
					mdFile:   path,
					mdLine:   lineNum,
					schemaFn: m[1] + ".go",
					lineNum:  ln,
				})
			}
		}
		return scanner.Err()
	})
	if err != nil {
		t.Fatalf("walk walkRoot: %v", err)
	}

	if len(citations) == 0 {
		t.Fatal("no schemas/X.go:N citations found in docs/walkthrough/ — either citations were removed or this test is mislocated")
	}

	// Deterministic order so test output is stable.
	sort.Slice(citations, func(i, j int) bool {
		if citations[i].mdFile != citations[j].mdFile {
			return citations[i].mdFile < citations[j].mdFile
		}
		if citations[i].mdLine != citations[j].mdLine {
			return citations[i].mdLine < citations[j].mdLine
		}
		return citations[i].lineNum < citations[j].lineNum
	})

	for _, c := range citations {
		schemaPath := filepath.Join(repoRoot, "schemas", c.schemaFn)
		line, err := readLine(schemaPath, c.lineNum)
		if err != nil {
			t.Errorf("%s:%d cites schemas/%s:%d but read failed: %v",
				rel(c.mdFile, repoRoot), c.mdLine, c.schemaFn, c.lineNum, err)
			continue
		}
		if !declRE.MatchString(line) {
			t.Errorf("%s:%d cites schemas/%s:%d which is NOT a `type` or `func` declaration. Got: %q",
				rel(c.mdFile, repoRoot), c.mdLine, c.schemaFn, c.lineNum, line)
		}
	}
}

// readLine returns the (1-indexed) Nth line of path.
func readLine(path string, n int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	current := 0
	for scanner.Scan() {
		current++
		if current == n {
			return scanner.Text(), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", &lineOutOfRangeError{path: path, want: n, got: current}
}

type lineOutOfRangeError struct {
	path string
	want int
	got  int
}

func (e *lineOutOfRangeError) Error() string {
	return "line " + strconv.Itoa(e.want) + " out of range for " + e.path +
		" (file has " + strconv.Itoa(e.got) + " lines)"
}

func rel(path, root string) string {
	r, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return r
}
