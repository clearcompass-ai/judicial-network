// Issue #67 Part B — §15 Schema Lifecycle deployment-level tests.
//
// Pins the governance contract:
//
//  1. CosignaturePolicy has a rule for each of the 4 §15 events.
//  2. Each rule requires MinSignerCosigners=2 — schema-level
//     governance is a two-judge minimum (symmetric with
//     judicial_appointment / clerk_appointment).
//  3. Publication / amendment / deprecation are intra-exchange;
//     adoption is cross-exchange-permitted (referencing another
//     network's published schema).
//  4. Prerequisite policy: publication has no prereqs (origin);
//     adoption / amendment / deprecation all require Hard prior
//     schema_publication ancestry on the log.
//  5. Walker scenarios that mirror the four use cases in the
//     docstring (TN SC publishes → Davidson adopts → SC amends
//     → SC deprecates) all admit cleanly given the right
//     ObservedEvents history.
package trial

import (
	"testing"

	prerequisites "github.com/baseproof/tooling/libs/prereq"

	"github.com/baseproof/tooling/libs/auth/policy"
)

// findRulePartB is the local lookup helper. Named "PartB" to
// avoid a collision with Part A's findRule helper when both PRs
// merge — once the issue #67 backlog closes, both can fold into
// a shared helpers_test.go.
func findRulePartB(rules []policy.CosignatureRule, eventType string) *policy.CosignatureRule {
	for i := range rules {
		if rules[i].EventType == eventType {
			return &rules[i]
		}
	}
	return nil
}

// TestPartB_SchemaLifecycle_CosignatureRulesWired pins that all
// 4 governance events have a CosignatureRule.
func TestPartB_SchemaLifecycle_CosignatureRulesWired(t *testing.T) {
	rules := CosignatureRules()
	for _, evt := range []string{
		"schema_publication",
		"schema_adoption",
		"schema_amendment",
		"schema_deprecation",
	} {
		t.Run(evt, func(t *testing.T) {
			rule := findRulePartB(rules, evt)
			if rule == nil {
				t.Fatalf("event %q has no CosignatureRule", evt)
			}
			if len(rule.AllowedFilerRoles) != 0 {
				t.Errorf("%q AllowedFilerRoles = %v, want empty (pure Signer-only)", evt, rule.AllowedFilerRoles)
			}
			if len(rule.RequiredSignerRoles) != 1 || rule.RequiredSignerRoles[0] != "judge" {
				t.Errorf("%q RequiredSignerRoles = %v, want [judge]", evt, rule.RequiredSignerRoles)
			}
			// Schema-level governance: 2-judge minimum.
			if rule.MinSignerCosigners < 2 {
				t.Errorf("%q MinSignerCosigners = %d, want >= 2 (schema-level governance)", evt, rule.MinSignerCosigners)
			}
		})
	}
}

// TestPartB_SchemaLifecycle_AdoptionCrossExchange pins the
// asymmetric exchange-scope rule: adoption can reference a
// publication from another network (a TN court adopting a
// federal-published schema), so IntraExchangeOnly is false.
// Publication / amendment / deprecation stay intra-exchange.
func TestPartB_SchemaLifecycle_AdoptionCrossExchange(t *testing.T) {
	rules := CosignatureRules()
	cases := []struct {
		evt           string
		wantIntraOnly bool
	}{
		{"schema_publication", true},
		{"schema_adoption", false},
		{"schema_amendment", true},
		{"schema_deprecation", true},
	}
	for _, c := range cases {
		t.Run(c.evt, func(t *testing.T) {
			rule := findRulePartB(rules, c.evt)
			if rule == nil {
				t.Fatalf("event %q not registered", c.evt)
			}
			if rule.IntraExchangeOnly != c.wantIntraOnly {
				t.Errorf("%q IntraExchangeOnly = %v, want %v", c.evt, rule.IntraExchangeOnly, c.wantIntraOnly)
			}
		})
	}
}

// TestPartB_SchemaLifecycle_PrerequisitesWired pins all 4 events
// have a prereq entry (even publication, which is empty).
func TestPartB_SchemaLifecycle_PrerequisitesWired(t *testing.T) {
	rules := PrerequisiteRules()
	for _, evt := range []string{
		"schema_publication",
		"schema_adoption",
		"schema_amendment",
		"schema_deprecation",
	} {
		if _, ok := rules[evt]; !ok {
			t.Errorf("event %q has no Prerequisite entry", evt)
		}
	}
}

// TestPartB_SchemaPublication_IsOriginEvent pins that
// schema_publication has NO prereqs — it is an origin event
// per dictionary §15 ("origin event (or referential, if
// predecessor is set)"). Predecessor handling is in the
// payload, not the prereq walker.
func TestPartB_SchemaPublication_IsOriginEvent(t *testing.T) {
	prs := PrerequisiteRules()["schema_publication"]
	if len(prs) != 0 {
		t.Errorf("schema_publication should have no prereqs (origin event); got %d", len(prs))
	}
}

// TestPartB_AdoptionRequiresPublication pins the §15 invariant:
// schema_adoption requires Hard prior schema_publication
// ancestor. The walker rejects an adoption with no publication
// on the chain.
func TestPartB_AdoptionRequiresPublication(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	// No publication on the chain → reject.
	v := w.Check("schema_adoption", prerequisites.EvalContext{})
	if v.OK {
		t.Error("schema_adoption with no prior publication must reject")
	}

	// Publication on the chain → admit.
	v = w.Check("schema_adoption", prerequisites.EvalContext{
		ObservedEvents: []string{"schema_publication"},
	})
	if !v.OK {
		t.Errorf("schema_adoption with prior publication must admit: %+v", v)
	}
}

// TestPartB_AmendmentRequiresPublication pins the parallel
// invariant for amendments: a schema_amendment without a
// prior schema_publication of the predecessor is rejected.
func TestPartB_AmendmentRequiresPublication(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	v := w.Check("schema_amendment", prerequisites.EvalContext{})
	if v.OK {
		t.Error("schema_amendment with no prior publication must reject")
	}
	v = w.Check("schema_amendment", prerequisites.EvalContext{
		ObservedEvents: []string{"schema_publication"},
	})
	if !v.OK {
		t.Errorf("schema_amendment with prior publication must admit: %+v", v)
	}
}

// TestPartB_DeprecationRequiresPublication pins the parallel
// invariant for deprecations.
func TestPartB_DeprecationRequiresPublication(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}
	v := w.Check("schema_deprecation", prerequisites.EvalContext{})
	if v.OK {
		t.Error("schema_deprecation with no prior publication must reject")
	}
	v = w.Check("schema_deprecation", prerequisites.EvalContext{
		ObservedEvents: []string{"schema_publication"},
	})
	if !v.OK {
		t.Errorf("schema_deprecation with prior publication must admit: %+v", v)
	}
}

// TestPartB_FullLifecycleWalk pins the end-to-end governance
// scenario: a network history with
//
//	publication → adoption → amendment → deprecation
//
// all admit cleanly because each later event sees the
// publication on the chain.
func TestPartB_FullLifecycleWalk(t *testing.T) {
	w := &prerequisites.Walker{Policy: MustPrerequisitePolicy()}

	// Publication admits at network genesis.
	if v := w.Check("schema_publication", prerequisites.EvalContext{}); !v.OK {
		t.Errorf("publication admit: %+v", v)
	}
	// Adoption admits with publication on chain.
	if v := w.Check("schema_adoption", prerequisites.EvalContext{
		ObservedEvents: []string{"schema_publication"},
	}); !v.OK {
		t.Errorf("adoption admit: %+v", v)
	}
	// Amendment admits with publication on chain.
	if v := w.Check("schema_amendment", prerequisites.EvalContext{
		ObservedEvents: []string{"schema_publication"},
	}); !v.OK {
		t.Errorf("amendment admit: %+v", v)
	}
	// Deprecation admits with publication on chain.
	if v := w.Check("schema_deprecation", prerequisites.EvalContext{
		ObservedEvents: []string{"schema_publication"},
	}); !v.OK {
		t.Errorf("deprecation admit: %+v", v)
	}
}
