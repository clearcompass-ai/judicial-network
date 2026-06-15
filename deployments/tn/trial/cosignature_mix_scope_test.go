/*
FILE PATH: deployments/tn/trial/cosignature_mix_scope_test.go

PRE-13b scope-at-publish — WS-B partial. Pins the gated event types that
now declare a RequiredScope, and exercises the libs ValidateScopeAtPublish
mechanism (auth/policy/cosignature_mix.go) over that authored subset.

NOTE: the full netmanifest.Build freeze is intentionally NOT wired yet —
ValidateScopeAtPublish validates the WHOLE rule set, and the remaining
gated events have no RequiredScope. This test covers the authored subset
+ the negative (a gated rule with no scope is rejected).
*/
package trial

import (
	"errors"
	"reflect"
	"testing"

	"github.com/baseproof/tooling/libs/auth/policy"
)

func TestScopeAtPublish_AuthoredTypes(t *testing.T) {
	// The gated event types authored in this WS-B slice, with the scope
	// token each cosigner's delegation must grant (drawn from the TN trial
	// role catalog's AllowedScope vocabulary).
	want := map[string][]string{
		"verdict":                    {"case_decision"},
		"final_judgment":             {"case_decision"},
		"transcript_publication":     {"transcript_publication"},
		"clerk_appointment":          {"invite:court_clerk"},
		"court_reporter_appointment": {"invite:court_reporter"},
	}

	rules := CosignatureRules()
	scoped := make([]policy.CosignatureRule, 0, len(want))
	for _, r := range rules {
		exp, ok := want[r.EventType]
		if !ok {
			continue
		}
		if !reflect.DeepEqual(r.RequiredScope, exp) {
			t.Errorf("%s: RequiredScope = %v, want %v", r.EventType, r.RequiredScope, exp)
		}
		scoped = append(scoped, r)
	}
	if len(scoped) != len(want) {
		t.Fatalf("found %d authored-scope rules, want %d", len(scoped), len(want))
	}

	// Every gated rule in the authored subset declares a scope ⇒ accepted.
	if err := policy.ValidateScopeAtPublish(scoped); err != nil {
		t.Fatalf("ValidateScopeAtPublish(authored subset): %v", err)
	}

	// A gated rule with no RequiredScope is rejected — the freeze that will
	// guard publish once every gated event is scoped.
	bad := []policy.CosignatureRule{{
		EventType:           "verdict_unscoped",
		RequiredSignerRoles: []string{"judge"},
	}}
	if err := policy.ValidateScopeAtPublish(bad); !errors.Is(err, policy.ErrGatedEventNoScope) {
		t.Fatalf("gated-no-scope: got %v, want ErrGatedEventNoScope", err)
	}
}
