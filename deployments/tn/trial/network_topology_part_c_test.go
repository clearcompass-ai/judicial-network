// Issue #67 Part C — §16 Network Topology deployment-level tests.
//
// Pins:
//  1. All 5 §16 events have CosignatureRules with judge-only signing.
//  2. network_fork is the strictest event: MinSignerCosigners=3.
//  3. mirror_* events are cross-exchange (they target external
//     networks); anchor_registration + scope_division_creation
//     are intra-exchange.
//  4. anchor_registration / network_fork / scope_division_creation
//     are origin events (no prereqs).
//  5. mirror_creation requires Hard prior delegation or schema_
//     publication; mirror_revocation requires Hard prior
//     mirror_creation.
//  6. End-to-end walks for each event admit/reject correctly.
package trial

import (
	"testing"

	prerequisites "github.com/baseproof/tooling/libs/prereq"

	"github.com/baseproof/tooling/libs/policy"
)

func findRulePartC(rules []policy.CosignatureRule, eventType string) *policy.CosignatureRule {
	for i := range rules {
		if rules[i].EventType == eventType {
			return &rules[i]
		}
	}
	return nil
}

func TestPartC_NetworkTopology_AllRegistered(t *testing.T) {
	rules := CosignatureRules()
	for _, evt := range []string{
		"anchor_registration",
		"mirror_creation",
		"mirror_revocation",
		"network_fork",
		"scope_division_creation",
	} {
		t.Run(evt, func(t *testing.T) {
			rule := findRulePartC(rules, evt)
			if rule == nil {
				t.Fatalf("%q missing", evt)
			}
			if len(rule.AllowedFilerRoles) != 0 {
				t.Errorf("%q has Filer roles; want empty", evt)
			}
			if len(rule.RequiredSignerRoles) != 1 || rule.RequiredSignerRoles[0] != "judge" {
				t.Errorf("%q signer = %v, want [judge]", evt, rule.RequiredSignerRoles)
			}
		})
	}
}

func TestPartC_NetworkFork_StrictestCosignerCount(t *testing.T) {
	rule := findRulePartC(CosignatureRules(), "network_fork")
	if rule == nil {
		t.Fatal("network_fork missing")
	}
	if rule.MinSignerCosigners < 3 {
		t.Errorf("network_fork MinSignerCosigners = %d, want >= 3 (strictest event)", rule.MinSignerCosigners)
	}
}

func TestPartC_MirrorEvents_CrossExchange(t *testing.T) {
	rules := CosignatureRules()
	for _, evt := range []string{"mirror_creation", "mirror_revocation", "network_fork"} {
		t.Run(evt, func(t *testing.T) {
			rule := findRulePartC(rules, evt)
			if rule == nil {
				t.Fatalf("%q missing", evt)
			}
			if rule.IntraExchangeOnly {
				t.Errorf("%q should be cross-exchange (targets external networks)", evt)
			}
		})
	}
}

func TestPartC_OriginEvents_NoPrereqs(t *testing.T) {
	rules := PrerequisiteRules()
	for _, evt := range []string{
		"anchor_registration",
		"network_fork",
		"scope_division_creation",
	} {
		t.Run(evt, func(t *testing.T) {
			prs, ok := rules[evt]
			if !ok {
				t.Fatalf("%q not in PrerequisiteRules", evt)
			}
			if len(prs) != 0 {
				t.Errorf("%q has prereqs (should be origin event); got %d", evt, len(prs))
			}
		})
	}
}

func TestPartC_MirrorCreation_RequiresEntryBeingMirrored(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	// No delegation or schema_publication on chain → reject.
	v := w.Check("mirror_creation", prerequisites.EvalContext{})
	if v.OK {
		t.Error("mirror_creation without delegation/schema_publication must reject")
	}

	// With a delegation on chain → admit.
	v = w.Check("mirror_creation", prerequisites.EvalContext{
		ObservedEvents: []string{"judicial_delegation"},
	})
	if !v.OK {
		t.Errorf("mirror_creation with delegation should admit: %+v", v)
	}

	// With a schema_publication on chain → admit (per dictionary §16).
	v = w.Check("mirror_creation", prerequisites.EvalContext{
		ObservedEvents: []string{"schema_publication"},
	})
	if !v.OK {
		t.Errorf("mirror_creation with schema_publication should admit: %+v", v)
	}
}

func TestPartC_MirrorRevocation_RequiresMirrorCreation(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	v := w.Check("mirror_revocation", prerequisites.EvalContext{})
	if v.OK {
		t.Error("mirror_revocation without mirror_creation must reject")
	}
	v = w.Check("mirror_revocation", prerequisites.EvalContext{
		ObservedEvents: []string{"mirror_creation"},
	})
	if !v.OK {
		t.Errorf("mirror_revocation with prior mirror_creation should admit: %+v", v)
	}
}

func TestPartC_FullFederationLifecycleWalk(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	// Goodlettsville onboards (anchor_registration is origin).
	if v := w.Check("anchor_registration", prerequisites.EvalContext{}); !v.OK {
		t.Errorf("anchor_registration: %+v", v)
	}
	// COA creates a mirror after Davidson published a delegation.
	if v := w.Check("mirror_creation", prerequisites.EvalContext{
		ObservedEvents: []string{"judicial_delegation"},
	}); !v.OK {
		t.Errorf("mirror_creation: %+v", v)
	}
	// Williamson is later revoked.
	if v := w.Check("mirror_revocation", prerequisites.EvalContext{
		ObservedEvents: []string{"mirror_creation"},
	}); !v.OK {
		t.Errorf("mirror_revocation: %+v", v)
	}
	// Hypothetical fork (origin).
	if v := w.Check("network_fork", prerequisites.EvalContext{}); !v.OK {
		t.Errorf("network_fork: %+v", v)
	}
	// Davidson creates drug-court division (origin in this v).
	if v := w.Check("scope_division_creation", prerequisites.EvalContext{}); !v.OK {
		t.Errorf("scope_division_creation: %+v", v)
	}
}
