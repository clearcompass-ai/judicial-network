package scenario

// The case generator: deterministically plans case_initiation filings for a
// jurisdiction, randomized across its divisions + case types but reproducible
// from the master seed.
//
// Each case is opened by a court_clerk (the primary signer at Signatures[0])
// and accepted by a SECOND court_clerk of the same court (the cosigner). This
// is the tn/trial case_initiation rule: a signer-only event (no filer / no
// bar credential — an attorney's appearance is a separate counsel_appearance
// event) whose cosignature mix requires one intra-exchange court_clerk besides
// the primary (verification/cosignature_signers.go excludes Signatures[0] from
// the threshold count, so the accepting clerk must be a distinct second clerk).
//
// GenerateCases builds the UNSIGNED entries (via cases.InitiateCase) and
// declares the accepting clerk in the payload's signed_by_capacities block so
// the verifier can resolve the cosigner's role + exchange with no off-log
// registry. Signatures are attached later by the cosigned sign-and-submit
// pipeline. Run AFTER Seed so the cosigner's on-log delegation_ref is present.

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/clearcompass-ai/judicial-network/cases"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// PlannedCase is one generated case_initiation: the docket metadata, the two
// court_clerks who sign it, and the unsigned entry ready for the cosigned
// sign-and-submit pipeline.
type PlannedCase struct {
	DocketNumber string
	Court        string
	Division     string
	Specialty    string
	CaseType     string
	Caption      string
	FiledDate    string
	Primary      *Principal // Signatures[0] — the clerk who opens the case
	Cosigner     *Principal // the accepting court_clerk (a Signatures[1+] cosigner)
	Entry        *envelope.Entry
}

// GenerateCases deterministically plans n case_initiation filings for reg's
// jurisdiction. Randomized across divisions + case types, but a pure function
// of (reg, n, masterSeed): the same inputs yield the same dockets, venues, and
// signing clerks every time.
func GenerateCases(reg *Registry, n int, masterSeed []byte) ([]*PlannedCase, error) {
	venues := buildVenues(reg)
	if len(venues) == 0 {
		return nil, fmt.Errorf("scenario: %s has no filing venue with >=2 clerks (case_initiation needs a clerk primary + a distinct clerk cosigner)", reg.Jurisdiction.Key)
	}
	rng := rand.New(rand.NewSource(seedInt64(masterSeed, "cases|"+reg.Jurisdiction.Key)))

	out := make([]*PlannedCase, 0, n)
	for i := 0; i < n; i++ {
		v := venues[rng.Intn(len(venues))]
		caseType := v.division.CaseTypes[rng.Intn(len(v.division.CaseTypes))]

		p := rng.Intn(len(v.clerks))
		q := (p + 1 + rng.Intn(len(v.clerks)-1)) % len(v.clerks) // distinct from p
		primary, cosigner := v.clerks[p], v.clerks[q]

		filed := filedTime(rng)
		pc, err := planCaseInitiation(reg.Jurisdiction, v, caseType, i, filed, primary, cosigner)
		if err != nil {
			return nil, err
		}
		out = append(out, pc)
	}
	return out, nil
}

// filingVenue is a (court, division) a case can be filed into, with the court's
// court_clerk pool.
type filingVenue struct {
	court    string
	division Division
	clerks   []*Principal
}

// buildVenues enumerates every (court, division) with a usable case type, but
// only for courts that have >=2 court_clerks (the case_initiation cosignature
// requirement).
func buildVenues(reg *Registry) []filingVenue {
	var venues []filingVenue
	for _, c := range reg.Jurisdiction.Courts {
		clerks := clerksOfCourt(reg, c.Name)
		if len(clerks) < 2 {
			continue
		}
		for _, d := range c.Divisions {
			if len(d.CaseTypes) == 0 {
				continue
			}
			venues = append(venues, filingVenue{court: c.Name, division: d, clerks: clerks})
		}
	}
	return venues
}

func clerksOfCourt(reg *Registry, court string) []*Principal {
	var out []*Principal
	for _, p := range reg.Clerks() {
		if p.Court == court {
			out = append(out, p)
		}
	}
	return out
}

// planCaseInitiation plans one case_initiation: the docket/venue metadata, the
// two clerks, and a sample unsigned entry. The accepting clerk is declared in
// signed_by_capacities; the division/specialty/caption ride the domain payload.
// The filed date is a historical 2026 payload value — distinct from the entry's
// protocol EventTime, which is set fresh (≈now) at submit time so the ledger's
// freshness gate accepts it.
func planCaseInitiation(j Jurisdiction, v filingVenue, caseType string, seq int, filed time.Time, primary, cosigner *Principal) (*PlannedCase, error) {
	pc := &PlannedCase{
		DocketNumber: docketNumber(v.division.Specialty, seq),
		Court:        v.court,
		Division:     v.division.Name,
		Specialty:    v.division.Specialty,
		CaseType:     caseType,
		Caption:      caseCaption(v.division.Specialty, seq),
		FiledDate:    filed.Format("2006-01-02"),
		Primary:      primary,
		Cosigner:     cosigner,
	}
	// Sample entry for inspection + tests; Provision rebuilds it fresh at
	// submit time via InitiationEntry so EventTime is within the freshness gate.
	entry, err := pc.InitiationEntry(j, time.Now().UTC().UnixMicro())
	if err != nil {
		return nil, err
	}
	pc.Entry = entry
	return pc, nil
}

// InitiationEntry builds a signable case_initiation entry for this planned case
// at the given protocol EventTime (microseconds). The accepting clerk is
// declared in signed_by_capacities (carrying its on-log delegation_ref, set by
// Seed) so the verifier resolves the cosigner's role + exchange with no off-log
// registry. Build it inline at submit time — a pre-built batch goes stale
// against the ledger's ≈5-minute freshness gate (cf. the ledger's
// _validation_determinism.sh: "built inline ... no staleness").
func (pc *PlannedCase) InitiationEntry(j Jurisdiction, eventTimeMicros int64) (*envelope.Entry, error) {
	sbc := schemas.SignedByCapacity{
		DID:           pc.Cosigner.DID,
		Role:          pc.Cosigner.Role, // court_clerk
		Exchange:      j.InstitutionalDID,
		DelegationRef: pc.Cosigner.Delegation, // present once Seed has run
	}
	res, err := cases.InitiateCase(cases.InitiationConfig{
		Destination:  j.ExchangeDID,
		SignerDID:    pc.Primary.DID,
		DocketNumber: pc.DocketNumber,
		CaseType:     pc.CaseType,
		FiledDate:    pc.FiledDate,
		ExtraPayload: map[string]interface{}{
			"specialty": pc.Specialty,
			"division":  pc.Division,
			"caption":   pc.Caption,
		},
		Cosigners: []schemas.SignedByCapacity{sbc},
		EventTime: eventTimeMicros,
	})
	if err != nil {
		return nil, fmt.Errorf("scenario: build case_initiation %s: %w", pc.DocketNumber, err)
	}
	return res.Entry, nil
}

// docketNumber renders a unique TN-style docket: <year>-<division-code>-<seq>.
// seq is the global case index, so the value is unique across the run.
func docketNumber(specialty string, seq int) string {
	return fmt.Sprintf("2026-%s-%05d", divisionCode(specialty), seq+1)
}

func divisionCode(specialty string) string {
	switch specialty {
	case "general_civil":
		return "GC"
	case "domestic":
		return "DM"
	case "probate":
		return "PB"
	case "juvenile":
		return "JV"
	case "criminal":
		return "CR"
	default:
		return "CV"
	}
}

// caseCaption renders a plausible case caption by specialty. Names are drawn
// deterministically from a fixed pool; juvenile captions use initials for
// confidentiality.
func caseCaption(specialty string, seq int) string {
	a := surnames[seq%len(surnames)]
	b := surnames[(seq*7+3)%len(surnames)]
	switch specialty {
	case "probate":
		return "In re Estate of " + a
	case "juvenile":
		return fmt.Sprintf("In re %c.%c.", a[0], b[0])
	case "domestic":
		return a + " v. " + b
	default:
		return a + " v. " + b
	}
}

// surnames is a small fixed pool for deterministic case captions (test
// population, not real litigants).
var surnames = []string{
	"Hairston", "Bryant", "Caldwell", "Pearson", "Whitfield", "Mosley",
	"Ferguson", "Sutton", "Holloway", "Vance", "Ramsey", "Dillard",
	"Kirkland", "Stinson", "Maddox", "Greer",
}

// filedTime picks a random day in 2026 (deterministic via rng).
func filedTime(rng *rand.Rand) time.Time {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return base.Add(time.Duration(rng.Intn(365)) * 24 * time.Hour)
}

// seedInt64 derives a stable int64 RNG seed from (masterSeed, label).
func seedInt64(masterSeed []byte, label string) int64 {
	s := deriveScalar(masterSeed, label, 0)
	return int64(binary.BigEndian.Uint64(s[:8]))
}
