/*
FILE PATH: deployments/TEMPLATE/rules/cosignature_mix_test.go

DESCRIPTION:
    Tests for the TEMPLATE cosignature-mix skeleton. Pins:
      - the skeleton compiles and validates,
      - exactly 1 rule (case_initiated) exists,
      - the rule is intra-exchange and judge-signed.
*/
package rules

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/policy"
)

func TestCosignatureRules_Validates(t *testing.T) {
	if _, err := policy.NewInMemoryPolicy(CosignatureRules()); err != nil {
		t.Errorf("TEMPLATE cosig rules failed to construct: %v", err)
	}
}

func TestCosignatureRules_OneRule(t *testing.T) {
	if got := len(CosignatureRules()); got != 1 {
		t.Errorf("TEMPLATE skeleton must ship 1 rule; got %d", got)
	}
}

func TestCosignatureRules_CaseInitiatedShape(t *testing.T) {
	r := CosignatureRules()[0]
	if r.EventType != "case_initiated" {
		t.Errorf("placeholder event_type drift: want case_initiated, got %q",
			r.EventType)
	}
	if !r.IntraExchangeOnly {
		t.Error("placeholder rule must be IntraExchangeOnly=true")
	}
	if len(r.RequiredSignerRoles) != 1 || r.RequiredSignerRoles[0] != "judge" {
		t.Errorf("placeholder RequiredSignerRoles drift: want [judge], got %v",
			r.RequiredSignerRoles)
	}
	if r.RequiresFiler() {
		t.Error("placeholder rule must not require a filer")
	}
}

func TestMustCosignaturePolicy_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustCosignaturePolicy panicked: %v", r)
		}
	}()
	_ = MustCosignaturePolicy()
}
