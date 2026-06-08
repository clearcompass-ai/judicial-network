package runner

import "testing"

// TestRecipesRegistered guards that every recipe self-registers via its init() —
// a new recipe file that compiles but whose Register call is missing/renamed would
// otherwise silently never appear in `e2e run` (the failure mode that looks like a
// stale binary). Names() is sourced from the same registry `e2e run` consults.
func TestRecipesRegistered(t *testing.T) {
	want := []string{
		"verify.pagination",
		"verify.walgc",
		"federation.proof.pgoff",
		"federation.dr",
	}
	for _, name := range want {
		if _, ok := registry[name]; !ok {
			t.Errorf("recipe %q not registered; known = %v", name, Names())
		}
	}
}
