/*
FILE PATH: deployments/tn/coa/cosignature_mix_test.go

DESCRIPTION:

	Tests for the TN COA cosignature-mix fixture. Pins:
	  - Every rule validates structurally.
	  - The vocabulary covers the v1.8 §7B appellate event
	    family.
	  - appellate_disposition requires ≥2 cosigners (panel
	    invariant).
	  - remand_affirmance is cross-exchange (cross-network ref
	    to trial root).
	  - No AllowedFilerRoles anywhere — appellate motions
	    originate at trial.
	  - Personnel events require ≥2 cosigners and are
	    intra-exchange.
*/
package coa

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/policy"
)

// ─── basic invariants ──────────────────────────────────────────────

func TestCosignatureRules_AllValid(t *testing.T) {
	if _, err := policy.NewInMemoryPolicy(CosignatureRules()); err != nil {
		t.Errorf("TN COA cosig rules failed to construct: %v", err)
	}
}

func TestMustCosignaturePolicy_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustCosignaturePolicy panicked: %v", r)
		}
	}()
	p := MustCosignaturePolicy()
	if got := len(p.List()); got == 0 {
		t.Error("TN COA cosig policy should have rules")
	}
}

func TestMustCosignaturePolicy_IndependentCalls(t *testing.T) {
	a := MustCosignaturePolicy()
	b := MustCosignaturePolicy()
	if a == b {
		t.Error("MustCosignaturePolicy should return a fresh policy per call")
	}
}

// ─── v1.8 §7B vocabulary ───────────────────────────────────────────

func TestCosignatureRules_AppellateFamilyPresent(t *testing.T) {
	p := MustCosignaturePolicy()
	for _, ev := range []string{
		"appellate_case_initiation",
		"appellate_opinion_publication",
		"appellate_opinion_participation",
		"appellate_disposition",
		"remand_affirmance",
	} {
		if _, err := p.Lookup(ev); err != nil {
			t.Errorf("v1.8 §7B event %q missing from COA cosig: %v", ev, err)
		}
	}
}

// ─── appellate_disposition: ≥2 panel cosigners ─────────────────────

func TestCosignatureRules_DispositionRequiresPanel(t *testing.T) {
	r, err := MustCosignaturePolicy().Lookup("appellate_disposition")
	if err != nil {
		t.Fatalf("appellate_disposition missing: %v", err)
	}
	if r.MinSignerCosigners < 2 {
		t.Errorf("appellate_disposition must require ≥2 cosigners (panel); got %d",
			r.MinSignerCosigners)
	}
	if !r.IntraExchangeOnly {
		t.Error("appellate_disposition must be intra-exchange (single panel)")
	}
}

// ─── remand_affirmance: cross-exchange ─────────────────────────────

func TestCosignatureRules_RemandAffirmanceCrossExchange(t *testing.T) {
	r, err := MustCosignaturePolicy().Lookup("remand_affirmance")
	if err != nil {
		t.Fatalf("remand_affirmance missing: %v", err)
	}
	if r.IntraExchangeOnly {
		t.Error("remand_affirmance must be cross-exchange (flows back to trial root)")
	}
}

// ─── no filer-driven events ────────────────────────────────────────

func TestCosignatureRules_NoFilerEvents(t *testing.T) {
	for _, r := range CosignatureRules() {
		if r.RequiresFiler() {
			t.Errorf("%s declares AllowedFilerRoles=%v; appellate vocab is filer-free",
				r.EventType, r.AllowedFilerRoles)
		}
	}
}

// ─── personnel events: ≥2 cosigners, intra-exchange ────────────────

func TestCosignatureRules_PersonnelEventsRequirePanel(t *testing.T) {
	personnel := []string{"judicial_appointment", "clerk_appointment"}
	p := MustCosignaturePolicy()
	for _, ev := range personnel {
		r, err := p.Lookup(ev)
		if err != nil {
			t.Errorf("%s missing: %v", ev, err)
			continue
		}
		if r.MinSignerCosigners < 2 {
			t.Errorf("%s must require ≥2 cosigners; got %d",
				ev, r.MinSignerCosigners)
		}
		if !r.IntraExchangeOnly {
			t.Errorf("%s must be intra-exchange-only", ev)
		}
	}
}

// ─── topology events: cross-exchange ───────────────────────────────

func TestCosignatureRules_TopologyEventsCrossExchange(t *testing.T) {
	topology := []string{
		"case_transfer_inbound",
		"case_transfer_outbound",
		"relay_attestation",
	}
	p := MustCosignaturePolicy()
	for _, ev := range topology {
		r, err := p.Lookup(ev)
		if err != nil {
			t.Errorf("%s missing: %v", ev, err)
			continue
		}
		if r.IntraExchangeOnly {
			t.Errorf("%s must be cross-exchange-permitted", ev)
		}
	}
}

// ─── opinion events: judge or chief_judge signs ────────────────────

func TestCosignatureRules_OpinionEventsJudgeOnly(t *testing.T) {
	opinionEvents := []string{
		"appellate_opinion_publication",
		"appellate_opinion_participation",
	}
	p := MustCosignaturePolicy()
	for _, ev := range opinionEvents {
		r, err := p.Lookup(ev)
		if err != nil {
			t.Errorf("%s missing: %v", ev, err)
			continue
		}
		// Required roles must be a subset of {judge, chief_judge}.
		for _, role := range r.RequiredSignerRoles {
			if role != "judge" && role != "chief_judge" {
				t.Errorf("%s has unexpected signer role %q",
					ev, role)
			}
		}
	}
}

// TestCosignatureRules_ExpectedCount pins the rule count so an
// accidental addition / deletion shows up in CI.
func TestCosignatureRules_ExpectedCount(t *testing.T) {
	const want = 10 // 4 appellate + remand + 2 personnel + 3 topology
	if got := len(CosignatureRules()); got != want {
		t.Errorf("TN COA cosig rule count: want %d, got %d", want, got)
	}
}
