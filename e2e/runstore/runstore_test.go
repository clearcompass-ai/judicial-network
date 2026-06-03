package runstore

import (
	"path/filepath"
	"testing"
)

func TestValidID(t *testing.T) {
	for _, ok := range []string{"a3f", "ZZ9", "000"} {
		if !ValidID(ok) {
			t.Fatalf("ValidID(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "ab", "abcd", "a-f", "a f"} {
		if ValidID(bad) {
			t.Fatalf("ValidID(%q) = true, want false", bad)
		}
	}
}

func TestGenID(t *testing.T) {
	for i := 0; i < 100; i++ {
		if id := GenID(); !ValidID(id) {
			t.Fatalf("GenID() = %q, not a valid id", id)
		}
	}
}

func TestLayout_MkdirsAndPaths(t *testing.T) {
	root := t.TempDir()
	l, err := NewUnder(root, "a3f")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Mkdirs(); err != nil {
		t.Fatal(err)
	}
	if l.Home != filepath.Join(root, "a3f") {
		t.Fatalf("Home = %q", l.Home)
	}
	for _, d := range []string{l.Certs, l.Fixtures, l.Identities, l.Diag} {
		if !filepathHasPrefix(d, l.Home) {
			t.Fatalf("%q is not under Home %q", d, l.Home)
		}
	}
	if _, err := NewUnder(root, "bad-id"); err == nil {
		t.Fatal("want error for invalid id")
	}
}

func filepathHasPrefix(p, prefix string) bool {
	rel, err := filepath.Rel(prefix, p)
	return err == nil && rel != ".." && len(rel) > 0 && rel[0] != '.'
}

func TestManifest_RoundTrip(t *testing.T) {
	root := t.TempDir()
	l, _ := NewUnder(root, "m7c")
	if l.IsProvisioned() {
		t.Fatal("fresh run should not be provisioned")
	}
	in := &Manifest{
		ID: "m7c", Preset: "federation", Network: "e2e-m7c",
		Networks: []NetworkManifest{
			{Name: "federal", LogDID: "did:web:x", QuorumK: 3, LedgerName: "e2e-m7c-federal-ledger", LedgerPort: 8080, JNPort: 8443},
			{Name: "tn", LogDID: "did:web:y", QuorumK: 2, LedgerName: "e2e-m7c-tn-ledger", LedgerPort: 8081, JNPort: 8444},
		},
	}
	if err := l.SaveManifest(in); err != nil {
		t.Fatal(err)
	}
	if !l.IsProvisioned() {
		t.Fatal("should be provisioned after SaveManifest")
	}
	out, err := l.LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	if out.Preset != "federation" || len(out.Networks) != 2 || out.Networks[1].LedgerPort != 8081 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	if err := l.Remove(); err != nil {
		t.Fatal(err)
	}
	if l.IsProvisioned() {
		t.Fatal("should not be provisioned after Remove")
	}
}

func TestListAndResolve(t *testing.T) {
	root := t.TempDir()
	// No runs yet: mustExist errors; otherwise a fresh id.
	if _, err := ResolveID("", root, true); err == nil {
		t.Fatal("want error resolving with mustExist and no runs")
	}
	if id, err := ResolveID("", root, false); err != nil || !ValidID(id) {
		t.Fatalf("fresh resolve: id=%q err=%v", id, err)
	}
	// Create two runs; latest-by-mtime is resolved.
	for _, id := range []string{"aaa", "bbb"} {
		l, _ := NewUnder(root, id)
		if err := l.SaveManifest(&Manifest{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	runs := ListRuns(root)
	if len(runs) != 2 {
		t.Fatalf("ListRuns = %v, want 2", runs)
	}
	if got, _ := ResolveID("aaa", root, true); got != "aaa" {
		t.Fatalf("explicit resolve = %q, want aaa", got)
	}
}
