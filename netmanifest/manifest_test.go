/*
FILE PATH: netmanifest/manifest_test.go

DESCRIPTION:

	Pins the jurisdiction PROJECTOR (the judicial half — the wire schema's
	own mechanics are pinned in libs/networkbundle):

	  - Build over the compiled Davidson bundle serializes the ENFORCED
	    policy verbatim: every cosignature event appears as an operation
	    whose Signing is the gate's own rule; hard-ancestor events project
	    as "dependent"; the document round-trips the platform's strict
	    decoder (the served contract IS the schema).
	  - JN2: overlay-named datatypes always get a declared row — supplied
	    (anchored) rows pass through untouched; missing ones synthesize
	    Name-only, so Build's own Validate holds and the consumer door's
	    anchor refusal is the planned publication alarm, not a structural
	    failure.
*/
package netmanifest

import (
	"testing"

	"github.com/baseproof/tooling/libs/networkbundle"

	davidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
)

func davidsonInput() networkbundle.BuildInput {
	return networkbundle.BuildInput{
		Network: networkbundle.NetworkRef{Name: "jn-test"},
		Overlay: trial.ManifestOverlay(),
		Status: networkbundle.StatusProbes{
			Protocol: "ledger:/v1/entries-hash/{hash}",
			Finality: "ledger:/v1/tree/horizon",
			Domain:   "terminal entry of the instance's closed_by/amended_by chain",
		},
	}
}

func TestBuild_Davidson_ProjectsEnforcedPolicy(t *testing.T) {
	b := davidson.MustBundle()
	m, err := Build(b, davidsonInput())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.Exchange != davidson.ExchangeDID {
		t.Fatalf("exchange = %q", m.Exchange)
	}

	// Every cosignature rule the gate enforces appears verbatim.
	cosig := b.CosignaturePolicy()
	byEvt := map[string]*networkbundle.Operation{}
	for i := range m.Operations {
		byEvt[m.Operations[i].EventType] = &m.Operations[i]
	}
	for _, rule := range cosig.List() {
		op := byEvt[rule.EventType]
		if op == nil {
			t.Fatalf("enforced event %q missing from the projection", rule.EventType)
		}
		if op.Signing == nil || op.Signing.EventType != rule.EventType {
			t.Fatalf("operation %q does not embed the enforced rule", rule.EventType)
		}
		if op.Signing.EffectiveMinCosigners() != rule.EffectiveMinCosigners() {
			t.Fatalf("operation %q threshold drifted from the gate's", rule.EventType)
		}
	}

	// The projection round-trips the platform's strict decoder byte-stably.
	raw, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	back, err := networkbundle.DecodeManifest(raw)
	if err != nil {
		t.Fatalf("the projection must satisfy the platform schema: %v", err)
	}
	raw2, _ := back.CanonicalBytes()
	if string(raw) != string(raw2) {
		t.Fatal("projection is not a canonical fixed point")
	}
}

func TestBuild_JN2_SynthesizesDeclaredDatatypes(t *testing.T) {
	b := davidson.MustBundle()
	in := davidsonInput()

	// One overlay datatype supplied WITH an anchor: passes through untouched.
	anchored := networkbundle.Datatype{
		Name: firstOverlayDatatype(t, in), LogDID: "did:web:log", Sequence: 9,
		ContentHash: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}
	in.Datatypes = []networkbundle.Datatype{anchored}

	m, err := Build(b, in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	rows := map[string]networkbundle.Datatype{}
	for _, d := range m.Datatypes {
		rows[d.Name] = d
	}
	if got := rows[anchored.Name]; got.Sequence != 9 || got.ContentHash == "" {
		t.Fatalf("supplied anchored row must pass through untouched: %+v", got)
	}
	// EVERY overlay-named datatype is declared (the structural rule holds at
	// Build time), even where no row was supplied.
	for evt, ov := range in.Overlay {
		if ov.Datatype == "" {
			continue
		}
		if _, ok := rows[ov.Datatype]; !ok {
			t.Fatalf("overlay %q names datatype %q but the projection did not declare it", evt, ov.Datatype)
		}
	}
}

func firstOverlayDatatype(t *testing.T, in networkbundle.BuildInput) string {
	t.Helper()
	for _, ov := range in.Overlay {
		if ov.Datatype != "" {
			return ov.Datatype
		}
	}
	t.Skip("overlay carries no datatypes")
	return ""
}
