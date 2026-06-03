package topology

import "testing"

// Every registered preset must resolve and validate.
func TestPresets_Resolve(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Fatal("no presets registered")
	}
	for _, name := range names {
		if _, err := Get(name); err != nil {
			t.Fatalf("preset %q: %v", name, err)
		}
	}
}

func TestSingle(t *testing.T) {
	s, err := Get("single")
	if err != nil {
		t.Fatal(err)
	}
	if s.NetworkCount() != 1 || s.TotalWitnesses() != 3 || s.TotalAuditors() != 2 {
		t.Fatalf("single = %s, want 1 network / 3 witnesses / 2 auditors", s.Summary())
	}
}

func TestFederation(t *testing.T) {
	s, err := Get("federation")
	if err != nil {
		t.Fatal(err)
	}
	if s.NetworkCount() != 3 {
		t.Fatalf("federation networks = %d, want 3", s.NetworkCount())
	}
	if s.TotalWitnesses() != 10 { // 4 + 3 + 3
		t.Fatalf("federation witnesses = %d, want 10 (4+3+3)", s.TotalWitnesses())
	}
	if s.SharedWitnesses != 2 || s.SharedAuditors != 2 {
		t.Fatalf("federation shared = (%d w, %d a), want (2, 2)", s.SharedWitnesses, s.SharedAuditors)
	}
}

// The headline extensibility property: a 5×20 topology is just a preset.
func TestMega_FiveByTwenty(t *testing.T) {
	s, err := Get("mega")
	if err != nil {
		t.Fatal(err)
	}
	if s.NetworkCount() != 5 {
		t.Fatalf("mega networks = %d, want 5", s.NetworkCount())
	}
	if s.TotalWitnesses() != 100 || s.TotalAuditors() != 100 {
		t.Fatalf("mega = %s, want 100 witnesses / 100 auditors (5×20)", s.Summary())
	}
}

// ...and the same shape is reachable ad-hoc from flags.
func TestFromFlags_FiveByTwenty(t *testing.T) {
	s, err := FromFlags(5, 20, 20, 7)
	if err != nil {
		t.Fatal(err)
	}
	if s.NetworkCount() != 5 || s.TotalWitnesses() != 100 || s.TotalAuditors() != 100 {
		t.Fatalf("from-flags = %s, want 5 networks / 100 witnesses / 100 auditors", s.Summary())
	}
}

func TestValidate_RejectsKGreaterThanWitnesses(t *testing.T) {
	s := StackSpec{Name: "bad", Networks: []NetworkSpec{
		{Name: "n1", QuorumK: 5, Witnesses: 3, Auditors: 1},
	}}
	if err := s.Validate(); err == nil {
		t.Fatal("want an error for quorum_k > witnesses")
	}
}

func TestValidate_RejectsSharedExceedingSmallestNetwork(t *testing.T) {
	s := StackSpec{
		Name: "bad",
		Networks: []NetworkSpec{
			{Name: "a", QuorumK: 2, Witnesses: 4, Auditors: 3},
			{Name: "b", QuorumK: 2, Witnesses: 3, Auditors: 3},
		},
		SharedWitnesses: 4, // exceeds the smallest network's 3
	}
	if err := s.Validate(); err == nil {
		t.Fatal("want an error for shared_witnesses exceeding the smallest network")
	}
}

func TestValidate_RejectsDuplicateNetworkNames(t *testing.T) {
	s := StackSpec{Name: "bad", Networks: []NetworkSpec{
		{Name: "n1", QuorumK: 1, Witnesses: 1, Auditors: 0},
		{Name: "n1", QuorumK: 1, Witnesses: 1, Auditors: 0},
	}}
	if err := s.Validate(); err == nil {
		t.Fatal("want an error for duplicate network names")
	}
}

func TestValidate_RejectsEmpty(t *testing.T) {
	if err := (StackSpec{Name: "empty"}).Validate(); err == nil {
		t.Fatal("want an error for a stack with no networks")
	}
}

func TestGet_UnknownPreset(t *testing.T) {
	if _, err := Get("nope"); err == nil {
		t.Fatal("want an error for an unknown preset")
	}
}
