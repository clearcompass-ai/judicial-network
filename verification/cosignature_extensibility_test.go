/*
FILE PATH: verification/cosignature_extensibility_test.go

DESCRIPTION:
    Pins the credential-extensibility contract: per-(actor × event)
    credential requirements are configured by the policy module, NOT
    by Go code. Adding a new required credential, or a new event with
    its own credential bag, is a JSON catalog change — code does not
    move.

    Two scenarios:
      - new event_type with multi-credential bag (bpr_number,
        state_id, federal_pacer_id) — verifier rejects on missing
        keys, accepts on full set, ignores extra unmentioned keys.
      - same actor (defense_counsel), TWO events with DIFFERENT
        credential demands — verifier reads the rule and gates
        accordingly.

    These two tests are the pin for "Capacity is extensible by design"
    promised in the v1.6 design conversation.
*/
package verification

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// TestCheck_CredentialExtensibility_NewKeyAddedByPolicy declares
// a custom event_type "specialty_filing" with three required
// credential keys and verifies:
//   - missing any one key → rejected
//   - all keys present (plus extras) → accepted
func TestCheck_CredentialExtensibility_NewKeyAddedByPolicy(t *testing.T) {
	customRule := policy.CosignatureRule{
		EventType:         "specialty_filing",
		AllowedFilerRoles: []schemas.FilerRole{schemas.FilerRoleDefenseCounsel},
		// Allow both clerk and judge as cosigners — the test fixture
		// only registers a clerk + a judge; either satisfies.
		RequiredSignerRoles: []string{"court_clerk", "judge"},
		IntraExchangeOnly:   true,
		RequiredCredentials: []string{
			"bpr_number", "state_id", "federal_pacer_id",
		},
	}
	pol, err := policy.NewInMemoryPolicy([]policy.CosignatureRule{customRule})
	if err != nil {
		t.Fatalf("NewInMemoryPolicy: %v", err)
	}
	res := buildResolver(t)

	makeCap := func(creds map[string]any) map[string]any {
		return map[string]any{
			"actor":       2,
			"role":        "defense_counsel",
			"did":         atyDID,
			"credentials": creds,
			"sworn_at":    time.Now().UTC().Format(time.RFC3339Nano),
		}
	}

	// All three creds present plus an extra unmentioned key — OK.
	good := buildEntry(clerkDID, map[string]any{
		"event_type": "specialty_filing",
		"filed_by_capacity": makeCap(map[string]any{
			"bpr_number":       "TN-12345",
			"state_id":         "TN-S-9876",
			"federal_pacer_id": "tn-fed-22",
			"firm":             "ignored extra key",
		}),
	}, atyDID, cosigJudge)
	v := CheckCosignature(good, pol, res, exchangeA)
	if !v.OK {
		t.Errorf("expected OK with all 3 creds + extra key: %s (%s)",
			v.Rejection, v.Reason)
	}

	// Missing federal_pacer_id — rejected.
	bad := buildEntry(clerkDID, map[string]any{
		"event_type": "specialty_filing",
		"filed_by_capacity": makeCap(map[string]any{
			"bpr_number": "TN-12345",
			"state_id":   "TN-S-9876",
		}),
	}, atyDID, cosigJudge)
	v = CheckCosignature(bad, pol, res, exchangeA)
	if v.Rejection != CosigRejectMissingCredential {
		t.Errorf("expected MissingCredential, got: %s (%s)", v.Rejection, v.Reason)
	}
}

// TestCheck_CredentialExtensibility_PerActorPerEvent pins that
// the same actor (defense_counsel) can carry DIFFERENT credentials
// for different events. The capacity payload shape stays identical;
// per-event policy rules drive the requirements.
func TestCheck_CredentialExtensibility_PerActorPerEvent(t *testing.T) {
	rules := []policy.CosignatureRule{
		{
			EventType:           "event_alpha",
			AllowedFilerRoles:   []schemas.FilerRole{schemas.FilerRoleDefenseCounsel},
			RequiredSignerRoles: []string{"court_clerk", "judge"},
			IntraExchangeOnly:   true,
			RequiredCredentials: []string{"bpr_number"},
		},
		{
			EventType:           "event_beta",
			AllowedFilerRoles:   []schemas.FilerRole{schemas.FilerRoleDefenseCounsel},
			RequiredSignerRoles: []string{"court_clerk", "judge"},
			IntraExchangeOnly:   true,
			RequiredCredentials: []string{"bpr_number", "state_id"},
		},
	}
	pol, err := policy.NewInMemoryPolicy(rules)
	if err != nil {
		t.Fatalf("NewInMemoryPolicy: %v", err)
	}
	res := buildResolver(t)

	makeEntry := func(eventType string, creds map[string]any) map[string]any {
		return map[string]any{
			"event_type": eventType,
			"filed_by_capacity": map[string]any{
				"actor":       2,
				"role":        "defense_counsel",
				"did":         atyDID,
				"credentials": creds,
				"sworn_at":    time.Now().UTC().Format(time.RFC3339Nano),
			},
		}
	}

	// alpha needs bpr_number only — OK with just that.
	alpha := buildEntry(clerkDID, makeEntry("event_alpha", map[string]any{
		"bpr_number": "TN-1",
	}), atyDID, cosigJudge)
	if v := CheckCosignature(alpha, pol, res, exchangeA); !v.OK {
		t.Errorf("alpha should accept bpr_number alone: %s (%s)",
			v.Rejection, v.Reason)
	}

	// beta needs bpr_number AND state_id — fails with only bpr_number.
	beta := buildEntry(clerkDID, makeEntry("event_beta", map[string]any{
		"bpr_number": "TN-1",
	}), atyDID, cosigJudge)
	if v := CheckCosignature(beta, pol, res, exchangeA); v.Rejection != CosigRejectMissingCredential {
		t.Errorf("beta should reject without state_id: %s (%s)",
			v.Rejection, v.Reason)
	}

	// beta with both creds — OK.
	betaOK := buildEntry(clerkDID, makeEntry("event_beta", map[string]any{
		"bpr_number": "TN-1",
		"state_id":   "TN-S-1",
	}), atyDID, cosigJudge)
	if v := CheckCosignature(betaOK, pol, res, exchangeA); !v.OK {
		t.Errorf("beta should accept bpr_number + state_id: %s (%s)",
			v.Rejection, v.Reason)
	}
}

// TestCheck_CredentialExtensibility_DifferentActorsDifferentBags
// pins per-actor (filer-role) credential extensibility:
// FilerRoleProsecutor and FilerRoleFiduciary are different actors
// with different credential expectations. The same payload shape
// carries both.
func TestCheck_CredentialExtensibility_DifferentActorsDifferentBags(t *testing.T) {
	rules := []policy.CosignatureRule{
		{
			EventType:           "prosecutor_event",
			AllowedFilerRoles:   []schemas.FilerRole{schemas.FilerRoleProsecutor},
			RequiredSignerRoles: []string{"court_clerk", "judge"},
			IntraExchangeOnly:   true,
			RequiredCredentials: []string{"bpr_number", "da_office_id"},
		},
		{
			EventType:           "fiduciary_event",
			AllowedFilerRoles:   []schemas.FilerRole{schemas.FilerRoleFiduciary},
			RequiredSignerRoles: []string{"court_clerk", "judge"},
			IntraExchangeOnly:   true,
			RequiredCredentials: []string{"letters_of_administration_ref", "bond_number"},
		},
	}
	pol, _ := policy.NewInMemoryPolicy(rules)
	res := buildResolver(t)

	prosecutor := buildEntry(clerkDID, map[string]any{
		"event_type": "prosecutor_event",
		"filed_by_capacity": map[string]any{
			"actor": 2, "role": "prosecutor", "did": atyDID,
			"credentials": map[string]any{
				"bpr_number":   "TN-1",
				"da_office_id": "DA-Davidson",
			},
			"sworn_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, atyDID, cosigJudge)
	if v := CheckCosignature(prosecutor, pol, res, exchangeA); !v.OK {
		t.Errorf("prosecutor: %s (%s)", v.Rejection, v.Reason)
	}

	fiduciary := buildEntry(clerkDID, map[string]any{
		"event_type": "fiduciary_event",
		"filed_by_capacity": map[string]any{
			"actor": 2, "role": "fiduciary", "did": atyDID,
			"credentials": map[string]any{
				"letters_of_administration_ref": "loa-2027-12",
				"bond_number":                   "B-99",
			},
			"sworn_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, atyDID, cosigJudge)
	if v := CheckCosignature(fiduciary, pol, res, exchangeA); !v.OK {
		t.Errorf("fiduciary: %s (%s)", v.Rejection, v.Reason)
	}
}
