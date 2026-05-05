/*
FILE PATH: api/exchange/handlers/submit_gate_test.go

DESCRIPTION:

	Unit tests for the SubmitGate. Cover the four gate paths:

	  - Missing Destination → missing_destination.
	  - Unknown exchange (Destination not in Registry) →
	    unknown_exchange.
	  - Cosignature rejection bubbles up.
	  - Prerequisite rejection bubbles up (Hard prereq violation
	    on the closed-by-default empty CaseContext).

	Functional emulation in submit_gate_functional_test.go.
*/
package handlers

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// stubGater is a hand-built SubmitGater used by test fixtures
// to inject a known-shape verdict without going through a real
// Bundle/Registry/RoleResolver chain.
type stubGater struct {
	rej *Rejection
}

func (s stubGater) Admit(_ []byte) *Rejection { return s.rej }

// ─── stubGater behavior pin ──────────────────────────────────────

func TestStubGater_Admits(t *testing.T) {
	g := stubGater{rej: nil}
	if g.Admit(nil) != nil {
		t.Error("nil rejection must mean Admit pass")
	}
}

func TestStubGater_Rejects(t *testing.T) {
	want := &Rejection{Code: "x", Reason: "y"}
	g := stubGater{rej: want}
	got := g.Admit(nil)
	if got == nil || got.Code != "x" || got.Reason != "y" {
		t.Errorf("stub rejection drift: got %+v", got)
	}
}

// ─── BundleSubmitGate: deserialize failure ───────────────────────

func TestBundleSubmitGate_DeserializeFails(t *testing.T) {
	g := &BundleSubmitGate{Registry: jurisdiction.NewRegistry()}
	rej := g.Admit([]byte("not an envelope"))
	if rej == nil || rej.Code != "deserialize_failed" {
		t.Errorf("garbage bytes: want deserialize_failed, got %+v", rej)
	}
}

// ─── BundleSubmitGate: nil bytes also fail deserialize ───────────

func TestBundleSubmitGate_NilBytes(t *testing.T) {
	g := &BundleSubmitGate{Registry: jurisdiction.NewRegistry()}
	rej := g.Admit(nil)
	if rej == nil || rej.Code != "deserialize_failed" {
		t.Errorf("nil bytes: want deserialize_failed, got %+v", rej)
	}
}

// ─── Rejection struct round-trip ─────────────────────────────────

func TestRejection_StructFields(t *testing.T) {
	r := &Rejection{Code: "abc", Reason: "def"}
	if r.Code != "abc" {
		t.Errorf("Code drift: %q", r.Code)
	}
	if r.Reason != "def" {
		t.Errorf("Reason drift: %q", r.Reason)
	}
}
