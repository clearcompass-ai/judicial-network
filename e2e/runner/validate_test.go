package runner

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseScales(t *testing.T) {
	got, err := parseScales("200000 500000,1000000\t2000000")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if want := []int{200000, 500000, 1000000, 2000000}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// a SINGLE value is a one-rung run (just 20K)
	if got, err := parseScales("20000"); err != nil || !reflect.DeepEqual(got, []int{20000}) {
		t.Fatalf("single-value got %v err %v, want [20000]", got, err)
	}
	// de-duplicates and sorts ascending
	if got, _ := parseScales("500000 200000 500000"); !reflect.DeepEqual(got, []int{200000, 500000}) {
		t.Fatalf("dedup/sort got %v", got)
	}
	if _, err := parseScales("abc"); err == nil {
		t.Fatal("want error on non-numeric scale")
	}
	if _, err := parseScales("   "); err == nil {
		t.Fatal("want error on empty spec")
	}
}

func TestParseTop(t *testing.T) {
	sample := `File: ledger
Type: inuse_space
Showing nodes accounting for 350.12MB, 95.30% of 367.39MB total
      flat  flat%   sum%        cum   cum%
  166.50MB 45.32% 45.32%   166.50MB 45.32%  github.com/dgraph-io/badger/v4/skl.newArena
   80.01MB 21.78% 67.10%    80.01MB 21.78%  github.com/baseproof/baseproof/core/smt.DecodeNode
   20.00MB  5.44% 72.54%    20.00MB  5.44%  runtime.allocm
`
	total, rows := parseTop(sample)
	if total != "367.39MB" {
		t.Fatalf("total=%q, want 367.39MB", total)
	}
	if len(rows) != 3 {
		t.Fatalf("rows=%d, want 3", len(rows))
	}
	if rows[0][0] != "166.50MB" || !strings.Contains(rows[0][1], "newArena") {
		t.Fatalf("row0=%v, want [166.50MB …newArena]", rows[0])
	}
	if !strings.Contains(rows[1][1], "DecodeNode") {
		t.Fatalf("row1=%v, want …DecodeNode", rows[1])
	}
}
