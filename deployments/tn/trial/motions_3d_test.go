/*
FILE PATH: deployments/tn/trial/motions_3d_test.go

DESCRIPTION:

	Tests for v1.8 §3D discovery & spoliation motions. Pins:
	  - 7 motion types (6 + 1 catch-all).
	  - motion_compel_discovery has Advisory discovery_filing prereq.
	  - motion_discovery_sanctions has Hard interlocutory_order
	    prereq (the order alleged to have been violated).
	  - motion_deem_facts_admitted has Advisory discovery_filing.
	  - All §3D motions are open to every Filer (advocate roles).
	  - Walker accepts Advisory misses but flags them; rejects
	    Hard misses.
*/
package trial

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/prerequisites"
)

func TestMotions3D_ExpectedEvents(t *testing.T) {
	want := map[string]bool{
		"motion_compel_discovery":     true,
		"motion_discovery_sanctions":  true,
		"motion_spoliation_sanctions": true,
		"motion_deem_facts_admitted":  true,
		"motion_protective_order":     true,
		"motion_quash_subpoena":       true,
		"motion_discovery_general":    true,
	}
	got := map[string]bool{}
	for _, m := range motions3D() {
		got[m.EventType] = true
	}
	if len(got) != len(want) {
		t.Errorf("§3D count: want %d, got %d", len(want), len(got))
	}
	for evt := range want {
		if !got[evt] {
			t.Errorf("§3D missing %q", evt)
		}
	}
}

func TestMotions3D_DiscoverySanctionsRequiresOrder(t *testing.T) {
	for _, m := range motions3D() {
		if m.EventType != "motion_discovery_sanctions" {
			continue
		}
		if len(m.AdditionalPrereqs) != 1 {
			t.Fatalf("want 1 additional prereq, got %d", len(m.AdditionalPrereqs))
		}
		p := m.AdditionalPrereqs[0]
		if p.Mode != prerequisites.PrereqModeHard {
			t.Errorf("must be Hard prereq, got %v", p.Mode)
		}
		if len(p.RequiredAncestor) != 1 || p.RequiredAncestor[0] != "interlocutory_order" {
			t.Errorf("ancestor drift: %v", p.RequiredAncestor)
		}
		return
	}
	t.Error("motion_discovery_sanctions missing")
}

func TestMotions3D_AdvisoryDiscoveryFiling(t *testing.T) {
	advisoryEvents := map[string]bool{
		"motion_compel_discovery":    true,
		"motion_deem_facts_admitted": true,
	}
	for _, m := range motions3D() {
		if !advisoryEvents[m.EventType] {
			continue
		}
		found := false
		for _, p := range m.AdditionalPrereqs {
			if p.Mode == prerequisites.PrereqModeAdvisory &&
				len(p.RequiredAncestor) == 1 &&
				p.RequiredAncestor[0] == "discovery_filing" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s must have Advisory discovery_filing prereq",
				m.EventType)
		}
	}
}

func TestMotions3D_CatchAllFlag(t *testing.T) {
	for _, m := range motions3D() {
		if m.EventType == "motion_discovery_general" {
			if !m.CustomTitleRequired {
				t.Error("motion_discovery_general must have CustomTitleRequired=true")
			}
			return
		}
	}
	t.Error("motion_discovery_general missing")
}

func TestMotions3D_InCosignatureRules(t *testing.T) {
	rules := MustCosignaturePolicy()
	for _, m := range motions3D() {
		if _, err := rules.Lookup(m.EventType); err != nil {
			t.Errorf("§3D event %q missing from CosignatureRules: %v",
				m.EventType, err)
		}
	}
}

// ─── functional walks ────────────────────────────────────────────

func TestFunctional_DiscoverySanctions_RequiresOrder(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("motion_discovery_sanctions", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if v.OK {
		t.Error("must reject without interlocutory_order")
	}

	v = w.Check("motion_discovery_sanctions", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated", "interlocutory_order"},
	})
	if !v.OK {
		t.Errorf("must accept with interlocutory_order: %s", v.Reason)
	}
}

// TestFunctional_CompelDiscovery_AdvisoryPassThroughs pins that
// motion_compel_discovery accepts even when discovery_filing is
// missing — the Advisory prereq surfaces a flag but doesn't
// block (real-world race tolerance).
func TestFunctional_CompelDiscovery_AdvisoryPassThroughs(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("motion_compel_discovery", prerequisites.CaseContext{
		ObservedEvents: []string{"case_initiated"},
	})
	if !v.OK {
		t.Errorf("Advisory prereq must NOT block: %s", v.Reason)
	}
	if len(v.Advisory) != 1 {
		t.Errorf("expected 1 Advisory violation, got %d", len(v.Advisory))
	}
}
