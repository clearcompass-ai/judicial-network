// Issue #67 Part A — §6 Court Orders deployment-level tests.
//
// Pins the wiring contract for the four daily-courtroom events
// (scheduling_order, interlocutory_order, protective_restraining_
// order, warrant_issuance_return):
//
//   1. CosignaturePolicy has a rule for each event.
//   2. Each rule's RequiredSignerRoles is [judge] (these are
//      pure Adjudicator-only judicial acts).
//   3. Each rule has IntraExchangeOnly=true (a judge cannot
//      issue an order in another court's case).
//   4. PrerequisitePolicy has a rule for each event.
//   5. scheduling_order, protective_restraining_order, and
//      warrant_issuance_return all require Hard case_initiation
//      ancestor (a judge cannot issue these on a non-existent
//      case).
//   6. interlocutory_order requires a Hard prior motion_* event
//      — the "rules on a prior motion" contract from dictionary
//      §6. Includes regression coverage that the prereq list
//      is non-empty (a future motion-catalog reshuffle that
//      empties motionEventNames() would otherwise silently
//      open admission to interlocutory_order entries without
//      any motion prereq).
package trial

import (
	"testing"

	prerequisites "github.com/clearcompass-ai/attesta-tools/libs/prereq"

	"github.com/clearcompass-ai/judicial-network/policy"
)

// hasPrefix is a small helper to avoid pulling in strings for
// the test sanity-check.
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// findRule returns the CosignatureRule for the named event in
// the trial bundle's cosignature mix, or nil if not registered.
func findRule(rules []policy.CosignatureRule, eventType string) *policy.CosignatureRule {
	for i := range rules {
		if rules[i].EventType == eventType {
			return &rules[i]
		}
	}
	return nil
}

// TestPartA_CourtOrders_AllRegisteredInCosignatureMix pins that
// every §6 event has a CosignatureRule. Without this, the
// admission gate would silently reject (no rule = no
// authorized signer set).
func TestPartA_CourtOrders_AllRegisteredInCosignatureMix(t *testing.T) {
	rules := CosignatureRules()
	for _, evt := range []string{
		"scheduling_order",
		"interlocutory_order",
		"protective_restraining_order",
		"warrant_issuance_return",
	} {
		t.Run(evt, func(t *testing.T) {
			rule := findRule(rules, evt)
			if rule == nil {
				t.Fatalf("event %q has no CosignatureRule", evt)
			}
			// All §6 events: pure Adjudicator-only acts.
			if len(rule.AllowedFilerRoles) != 0 {
				t.Errorf("event %q AllowedFilerRoles = %v, want empty (pure Signer-only)", evt, rule.AllowedFilerRoles)
			}
			// All §6 events: judge-signed.
			if len(rule.RequiredSignerRoles) != 1 || rule.RequiredSignerRoles[0] != "judge" {
				t.Errorf("event %q RequiredSignerRoles = %v, want [judge]", evt, rule.RequiredSignerRoles)
			}
			// All §6 events: intra-exchange.
			if !rule.IntraExchangeOnly {
				t.Errorf("event %q IntraExchangeOnly = false, want true (a judge cannot issue orders in another court's case)", evt)
			}
		})
	}
}

// TestPartA_CourtOrders_PrerequisitesWired pins that every §6
// event has a prerequisite rule (the prereq walker would
// otherwise admit any sequence).
func TestPartA_CourtOrders_PrerequisitesWired(t *testing.T) {
	rules := PrerequisiteRules()
	for _, evt := range []string{
		"scheduling_order",
		"interlocutory_order",
		"protective_restraining_order",
		"warrant_issuance_return",
	} {
		t.Run(evt, func(t *testing.T) {
			prs, ok := rules[evt]
			if !ok {
				t.Fatalf("event %q has no Prerequisite entry", evt)
			}
			if len(prs) == 0 {
				t.Errorf("event %q Prerequisite entry empty (would silently admit any sequence)", evt)
			}
		})
	}
}

// TestPartA_CourtOrdersRequireCaseInitiation pins the Hard
// case_initiation ancestor invariant for the three event types
// that need it. A judge cannot issue these on a non-existent
// case. The prereq walker enforces; this test pins the
// declaration.
func TestPartA_CourtOrdersRequireCaseInitiation(t *testing.T) {
	rules := PrerequisiteRules()
	for _, evt := range []string{
		"scheduling_order",
		"protective_restraining_order",
		"warrant_issuance_return",
	} {
		t.Run(evt, func(t *testing.T) {
			prs := rules[evt]
			var foundCaseInit bool
			for _, p := range prs {
				if p.Mode != prerequisites.PrereqModeHard {
					continue
				}
				for _, a := range p.RequiredAncestor {
					if a == "case_initiation" {
						foundCaseInit = true
					}
				}
			}
			if !foundCaseInit {
				t.Errorf("event %q does not require Hard case_initiation ancestor", evt)
			}
		})
	}
}

// TestPartA_InterlocutoryOrderRequiresPriorMotion pins the
// substantive §6 rule for interlocutory_order: it MUST require
// at least one motion_* ancestor (the "rules on a prior motion"
// contract). The motionEventNames() helper enumerates the §3A-
// §3I motion catalog; if that catalog ever ships empty, this
// test catches the silent regression.
func TestPartA_InterlocutoryOrderRequiresPriorMotion(t *testing.T) {
	rules := PrerequisiteRules()
	prs, ok := rules["interlocutory_order"]
	if !ok {
		t.Fatal("interlocutory_order missing from prereq rules")
	}
	var motionAncestors []string
	for _, p := range prs {
		if p.Mode != prerequisites.PrereqModeHard {
			continue
		}
		motionAncestors = append(motionAncestors, p.RequiredAncestor...)
	}
	if len(motionAncestors) == 0 {
		t.Fatal("interlocutory_order has no Hard prereqs (silent admission of orderless rulings)")
	}
	// Sanity-check the §3 catalog prefix: every ancestor should
	// be a §3 event — typically "motion_*" but post-conviction
	// proceedings (§3H) use "petition_*". Accept both.
	for _, a := range motionAncestors {
		if !(hasPrefix(a, "motion_") || hasPrefix(a, "petition_")) {
			t.Errorf("interlocutory_order ancestor %q is not a §3 motion/petition event", a)
		}
	}
	// Regression guard: ensure the catalog isn't down to a
	// single bookkeeping entry (a future motion-catalog
	// reorganization could otherwise drop us to one or two
	// names without anyone noticing).
	if len(motionAncestors) < 10 {
		t.Errorf("interlocutory_order ancestor count = %d, expected >= 10 (motion catalog reshuffle?)",
			len(motionAncestors))
	}
}
