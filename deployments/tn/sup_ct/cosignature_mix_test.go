/*
FILE PATH: deployments/tn/sup_ct/cosignature_mix_test.go

DESCRIPTION:

	Tests for the TN Sup Ct cosig fixture. Pins the canonical
	appellate-family rules AND the cross-exchange disciplinary
	revocation rule that distinguishes Sup Ct from COA.
*/
package sup_ct

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/policy"
)

func TestCosignatureRules_AllValid(t *testing.T) {
	if _, err := policy.NewInMemoryPolicy(CosignatureRules()); err != nil {
		t.Errorf("TN Sup Ct cosig rules failed to construct: %v", err)
	}
}

func TestMustCosignaturePolicy_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustCosignaturePolicy panicked: %v", r)
		}
	}()
	if got := len(MustCosignaturePolicy().List()); got == 0 {
		t.Error("Sup Ct cosig policy should have rules")
	}
}

// ─── canonical appellate family present ──────────────────────────

func TestCosignatureRules_AppellateFamily(t *testing.T) {
	p := MustCosignaturePolicy()
	for _, ev := range []string{
		"appellate_case_initiation",
		"appellate_opinion_publication",
		"appellate_opinion_participation",
		"appellate_disposition",
		"remand_affirmance",
	} {
		if _, err := p.Lookup(ev); err != nil {
			t.Errorf("appellate family event %q missing: %v", ev, err)
		}
	}
}

// ─── en-banc disposition requires majority ──────────────────────

func TestCosignatureRules_DispositionMajority(t *testing.T) {
	r, err := MustCosignaturePolicy().Lookup("appellate_disposition")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if r.MinSignerCosigners < 3 {
		t.Errorf("Sup Ct disposition must require ≥3 cosigners (majority of 5); got %d",
			r.MinSignerCosigners)
	}
	if !r.IntraExchangeOnly {
		t.Error("disposition must be intra-exchange (single en-banc panel)")
	}
}

// ─── §12C cross-exchange revocation: the v0.7.0 rule ─────────────

func TestCosignatureRules_CrossExchangeRevocation(t *testing.T) {
	r, err := MustCosignaturePolicy().Lookup("authority_revocation_disciplinary")
	if err != nil {
		t.Fatalf("authority_revocation_disciplinary missing: %v", err)
	}
	if r.IntraExchangeOnly {
		t.Error("Sup Ct authority_revocation_disciplinary MUST be cross-exchange (target Signer is on a trial county exchange)")
	}
	if r.MinSignerCosigners < 3 {
		t.Errorf("revocation must require ≥3 Justices; got %d",
			r.MinSignerCosigners)
	}
	hasJustice := false
	for _, role := range r.RequiredSignerRoles {
		if role == "justice" {
			hasJustice = true
			break
		}
	}
	if !hasJustice {
		t.Error("revocation must include 'justice' in RequiredSignerRoles")
	}
}

// ─── no Filer events at the Sup Ct ────────────────────────────────

func TestCosignatureRules_NoFilerEvents(t *testing.T) {
	for _, r := range CosignatureRules() {
		if r.RequiresFiler() {
			t.Errorf("%s declares AllowedFilerRoles; Sup Ct cosig is filer-free",
				r.EventType)
		}
	}
}

// ─── personnel events: ≥3 cosigners (majority) ───────────────────

func TestCosignatureRules_PersonnelMajority(t *testing.T) {
	for _, ev := range []string{
		"judicial_appointment",
		"clerk_appointment",
	} {
		r, err := MustCosignaturePolicy().Lookup(ev)
		if err != nil {
			t.Errorf("%s missing: %v", ev, err)
			continue
		}
		if r.MinSignerCosigners < 3 {
			t.Errorf("%s must require ≥3 cosigners; got %d",
				ev, r.MinSignerCosigners)
		}
	}
}

func TestCosignatureRules_ExpectedCount(t *testing.T) {
	const want = 11 // 4 appellate + remand + revocation +
	//                 2 personnel + 3 topology
	if got := len(CosignatureRules()); got != want {
		t.Errorf("Sup Ct cosig rule count: want %d, got %d", want, got)
	}
}
