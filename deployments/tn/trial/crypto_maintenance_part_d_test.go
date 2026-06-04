// Issue #67 Part D — §14 Crypto & Key Maintenance deployment-level tests.
package trial

import (
	"testing"

	prerequisites "github.com/baseproof/tooling/libs/prereq"

	"github.com/clearcompass-ai/judicial-network/policy"
)

func findRulePartD(rules []policy.CosignatureRule, eventType string) *policy.CosignatureRule {
	for i := range rules {
		if rules[i].EventType == eventType {
			return &rules[i]
		}
	}
	return nil
}

func TestPartD_CryptoMaintenance_Registered(t *testing.T) {
	rules := CosignatureRules()
	for _, evt := range []string{
		"institutional_key_rotation",
		"mofn_escrow_recovery_execution",
	} {
		t.Run(evt, func(t *testing.T) {
			rule := findRulePartD(rules, evt)
			if rule == nil {
				t.Fatalf("%q missing", evt)
			}
			if len(rule.RequiredSignerRoles) != 1 || rule.RequiredSignerRoles[0] != "judge" {
				t.Errorf("%q signer = %v, want [judge]", evt, rule.RequiredSignerRoles)
			}
		})
	}
}

// TestPartD_EscrowRecoveryStrictestCosigners pins the substantive
// continuity invariant: escrow recovery requires 3-judge minimum
// (strictest among the continuity events).
func TestPartD_EscrowRecoveryStrictestCosigners(t *testing.T) {
	rule := findRulePartD(CosignatureRules(), "mofn_escrow_recovery_execution")
	if rule == nil {
		t.Fatal("recovery rule missing")
	}
	if rule.MinSignerCosigners < 3 {
		t.Errorf("escrow recovery MinSignerCosigners = %d, want >= 3", rule.MinSignerCosigners)
	}
}

func TestPartD_KeyRotation_RequiresPriorAppointment(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("institutional_key_rotation", prerequisites.CaseContext{})
	if v.OK {
		t.Error("rotation without appointment must reject")
	}

	v = w.Check("institutional_key_rotation", prerequisites.CaseContext{
		ObservedEvents: []string{"judicial_appointment"},
	})
	if !v.OK {
		t.Errorf("rotation with appointment should admit: %+v", v)
	}
}

func TestPartD_EscrowRecovery_RequiresPriorAppointment(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	v := w.Check("mofn_escrow_recovery_execution", prerequisites.CaseContext{})
	if v.OK {
		t.Error("recovery without prior appointment must reject")
	}

	v = w.Check("mofn_escrow_recovery_execution", prerequisites.CaseContext{
		ObservedEvents: []string{"judicial_appointment"},
	})
	if !v.OK {
		t.Errorf("recovery with prior appointment should admit: %+v", v)
	}
}
