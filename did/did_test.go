package judicialdid

import (
	"testing"
)

func TestCourtMapping_MethodSet(t *testing.T) {
	m := CourtMapping()
	if m.Method == "" {
		t.Error("CourtMapping.Method must be set")
	}
	if m.TargetMethod == "" {
		t.Error("CourtMapping.TargetMethod must be set")
	}
}

func TestJNetMapping_MethodSet(t *testing.T) {
	m := JNetMapping()
	if m.Method == "" {
		t.Error("JNetMapping.Method must be set")
	}
	if m.TargetMethod == "" {
		t.Error("JNetMapping.TargetMethod must be set")
	}
}

func TestCCRMapping_MethodSet(t *testing.T) {
	m := CCRMapping()
	if m.Method == "" {
		t.Error("CCRMapping.Method must be set")
	}
}

func TestAllMappings_Returns3(t *testing.T) {
	mappings := AllMappings()
	if len(mappings) != 3 {
		t.Errorf("AllMappings = %d, want 3", len(mappings))
	}
}

func TestAllMappings_DistinctMethods(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range AllMappings() {
		if seen[m.Method] {
			t.Errorf("duplicate method: %s", m.Method)
		}
		seen[m.Method] = true
	}
}

func TestAllMappings_AllHaveTargetMethod(t *testing.T) {
	for i, m := range AllMappings() {
		if m.TargetMethod == "" {
			t.Errorf("mapping %d: TargetMethod empty", i)
		}
	}
}
