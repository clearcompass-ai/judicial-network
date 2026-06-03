package runner

import "testing"

func TestCoreRecipesRegistered(t *testing.T) {
	names := Names()
	want := map[string]bool{"smoke": false, "audit.tiles": false}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for n, seen := range want {
		if !seen {
			t.Fatalf("recipe %q not registered (have %v)", n, names)
		}
	}
}

func TestSelect(t *testing.T) {
	// by name substring (fragment unique to audit.tiles — "audit" alone now also
	// matches verify.auditor, which is correct substring behavior)
	if got := Select([]string{"tiles"}, nil); len(got) != 1 || got[0].Name != "audit.tiles" {
		t.Fatalf("Select(name=tiles) = %v, want [audit.tiles]", names(got))
	}
	// by tag
	if got := Select(nil, []string{"smoke"}); len(got) != 1 || got[0].Name != "smoke" {
		t.Fatalf("Select(tag=smoke) = %v, want [smoke]", names(got))
	}
	// empty filters match all registered recipes
	if got := Select(nil, nil); len(got) != len(Names()) {
		t.Fatalf("Select(nil,nil) = %d, want all %d", len(got), len(Names()))
	}
	// no match
	if got := Select([]string{"nope"}, nil); len(got) != 0 {
		t.Fatalf("Select(name=nope) = %v, want none", names(got))
	}
}

func names(rs []Recipe) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Name
	}
	return out
}
