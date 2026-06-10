package netmanifest_test

// manifest_test.go — the describe projection over the REAL Davidson bundle
// (the same compiled policy the SubmitGate enforces), so the test proves the
// served contract on production rules, not a fixture. Black-box package: the
// trial framework imports netmanifest for its overlay, so an internal test
// importing davidson would cycle.

import (
	"testing"

	davidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"

	. "github.com/clearcompass-ai/judicial-network/netmanifest"
)

func davidsonManifest(t *testing.T) *Manifest {
	t.Helper()
	m, err := Build(davidson.MustBundle(), BuildInput{
		Network: NetworkRef{Name: "tn-davidson", QuorumK: 2},
		Overlay: trial.ManifestOverlay(),
		Endpoints: []Endpoint{
			{ID: "ledger", URL: "https://ledger.test:8443", Transport: Transport{TLS: "server-verify"}, Status: "/healthz"},
			{ID: "gate", URL: "https://gate.test:9443", Transport: Transport{TLS: "mtls"}, Status: "/readyz", DependsOn: []string{"ledger"}},
		},
		Admission: Admission{Payment: []string{"credit", "pow"}, Gating: "write-authorization", WriteVia: "gate"},
		Submit:    Submit{Endpoint: "gate", Path: "/v1/entries/submit"},
		Status: StatusProbes{
			Protocol: "ledger:/v1/entries-hash/{hash}",
			Finality: "ledger:/v1/tree/horizon",
			Domain:   "terminal entry of the instance's closed_by/amended_by chain",
		},
	})
	if err != nil {
		t.Fatalf("Build(davidson): %v", err)
	}
	return m
}

func opByType(m *Manifest, evt string) *Operation {
	for i := range m.Operations {
		if m.Operations[i].EventType == evt {
			return &m.Operations[i]
		}
	}
	return nil
}

func TestBuild_Davidson_ProjectsEnforcedPolicy(t *testing.T) {
	m := davidsonManifest(t)

	if m.Exchange != davidson.ExchangeDID {
		t.Fatalf("exchange = %q, want %q", m.Exchange, davidson.ExchangeDID)
	}
	if len(m.Operations) == 0 || len(m.Roles) == 0 {
		t.Fatalf("empty projection: ops=%d roles=%d", len(m.Operations), len(m.Roles))
	}

	// case_initiation: an ORIGIN whose signing block is the enforced rule
	// (court_clerk cosigner, intra-exchange) — projected verbatim.
	ci := opByType(m, "case_initiation")
	if ci == nil {
		t.Fatal("case_initiation missing from the projection")
	}
	if ci.Kind != "origin" {
		t.Errorf("case_initiation kind = %q, want origin", ci.Kind)
	}
	if ci.Signing == nil || !ci.Signing.IntraExchangeOnly {
		t.Errorf("case_initiation signing not projected verbatim: %+v", ci.Signing)
	}

	// counsel_appearance: DEPENDENT (hard case_initiation ancestor) with the
	// enforced filer + credential requirements visible on the wire.
	ca := opByType(m, "counsel_appearance")
	if ca == nil {
		t.Fatal("counsel_appearance missing")
	}
	if ca.Kind != "dependent" {
		t.Errorf("counsel_appearance kind = %q, want dependent", ca.Kind)
	}
	if ca.Signing == nil || len(ca.Signing.RequiredCredentials) == 0 {
		t.Errorf("counsel_appearance lost its credential requirement: %+v", ca.Signing)
	}
	foundHardCaseInit := false
	for _, r := range ca.Requires {
		for _, anc := range r.RequiredAncestor {
			if anc == "case_initiation" {
				foundHardCaseInit = true
			}
		}
	}
	if !foundHardCaseInit {
		t.Error("counsel_appearance requires-edge to case_initiation not projected")
	}
}

func TestManifest_DAGAndOrder(t *testing.T) {
	m := davidsonManifest(t)

	order := m.TopoOrder()
	if len(order) != len(m.Operations) {
		t.Fatalf("topo order covers %d of %d operations", len(order), len(m.Operations))
	}
	pos := make(map[string]int, len(order))
	for i, evt := range order {
		pos[evt] = i
	}
	// A scenario driver submits case_initiation before its dependents.
	if pos["case_initiation"] > pos["counsel_appearance"] {
		t.Errorf("topo order puts counsel_appearance (%d) before case_initiation (%d)",
			pos["counsel_appearance"], pos["case_initiation"])
	}

	// Reverse-dependency walk: the monitoring cascade for case_initiation must
	// reach its hard dependents.
	deps := m.DependentsOf("case_initiation")
	want := map[string]bool{}
	for _, d := range deps {
		want[d] = true
	}
	if !want["counsel_appearance"] || !want["responsive_pleading"] {
		t.Errorf("DependentsOf(case_initiation) missing direct hard dependents: %v", deps)
	}
}

func TestManifest_WireRoundTripAndHashStability(t *testing.T) {
	m := davidsonManifest(t)

	b1, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	h1, err := m.ContentHash()
	if err != nil {
		t.Fatal(err)
	}

	got, err := Decode(b1)
	if err != nil {
		t.Fatalf("Decode(CanonicalBytes): %v", err)
	}
	h2, err := got.ContentHash()
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("content hash not stable across encode/decode — the on-log pin would not verify")
	}
	if got.Exchange != m.Exchange || len(got.Operations) != len(m.Operations) {
		t.Fatalf("round-trip lost content: exchange=%q ops=%d", got.Exchange, len(got.Operations))
	}
}

func TestValidate_RejectsStructuralBreaks(t *testing.T) {
	m := davidsonManifest(t)

	// A lifecycle edge to an unknown operation is authoring drift.
	m.Operations[0].ClosedBy = []string{"not_a_real_event"}
	if err := m.Validate(); err == nil {
		t.Error("Validate accepted closed_by → unknown operation")
	}
	m.Operations[0].ClosedBy = nil

	// Submit must target a declared endpoint.
	m.Submit.Endpoint = "nope"
	if err := m.Validate(); err == nil {
		t.Error("Validate accepted submit.endpoint → unknown endpoint")
	}
}
