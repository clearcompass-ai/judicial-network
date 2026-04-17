/*
FILE PATH: tests/did_mapping_test.go

Tests for did/mappings.go — vendor DID method translations.
*/
package tests

import (
	"testing"

	judicialdid "github.com/clearcompass-ai/judicial-network/did"
)

func TestCourtMapping_Fields(t *testing.T) {
	m := judicialdid.CourtMapping()
	if m.Method != "court" {
		t.Errorf("Method = %q, want %q", m.Method, "court")
	}
	if m.DomainSuffix != ".court.gov" {
		t.Errorf("DomainSuffix = %q, want %q", m.DomainSuffix, ".court.gov")
	}
	if m.TargetMethod != "web" {
		t.Errorf("TargetMethod = %q, want %q", m.TargetMethod, "web")
	}
	if m.TransformFunc != nil {
		t.Error("TransformFunc should be nil (default reversal)")
	}
}

func TestJNetMapping_Fields(t *testing.T) {
	m := judicialdid.JNetMapping()
	if m.Method != "jnet" {
		t.Errorf("Method = %q, want %q", m.Method, "jnet")
	}
	if m.DomainSuffix != ".jnet.gov" {
		t.Errorf("DomainSuffix = %q, want %q", m.DomainSuffix, ".jnet.gov")
	}
	if m.TargetMethod != "web" {
		t.Errorf("TargetMethod = %q, want %q", m.TargetMethod, "web")
	}
}

func TestCCRMapping_Fields(t *testing.T) {
	m := judicialdid.CCRMapping()
	if m.Method != "ccr" {
		t.Errorf("Method = %q, want %q", m.Method, "ccr")
	}
	if m.DomainSuffix != ".ccr.org" {
		t.Errorf("DomainSuffix = %q, want %q", m.DomainSuffix, ".ccr.org")
	}
	if m.TargetMethod != "web" {
		t.Errorf("TargetMethod = %q, want %q", m.TargetMethod, "web")
	}
}

func TestAllMappings_Count(t *testing.T) {
	all := judicialdid.AllMappings()
	if len(all) != 3 {
		t.Errorf("AllMappings returned %d, want 3", len(all))
	}
}

func TestAllMappings_Methods(t *testing.T) {
	all := judicialdid.AllMappings()
	methods := map[string]bool{}
	for _, m := range all {
		methods[m.Method] = true
	}
	for _, expected := range []string{"court", "jnet", "ccr"} {
		if !methods[expected] {
			t.Errorf("AllMappings missing method %q", expected)
		}
	}
}

func TestAllMappings_AllTargetWeb(t *testing.T) {
	for _, m := range judicialdid.AllMappings() {
		if m.TargetMethod != "web" {
			t.Errorf("Mapping %q targets %q, want %q", m.Method, m.TargetMethod, "web")
		}
	}
}
