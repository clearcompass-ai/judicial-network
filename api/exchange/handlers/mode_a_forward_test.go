/*
FILE PATH: api/exchange/handlers/mode_a_forward_test.go

DESCRIPTION:

	Pins the PAYMENT-axis (Mode A) forward at the single submit chokepoint
	(submitToLedger). When Dependencies.LedgerCreditToken is set, the JN relays
	it as Authorization: Bearer on the ledger hop — the ledger then authenticates
	the forward against its sessions table, SKIPS Mode B PoW, and deducts one
	credit (its balance>0 gate is the backstop). Empty token ⇒ no Authorization
	header (Mode B: the entry carries its own PoW stamp), preserving the prior
	posture. This axis is ORTHOGONAL to the gate-5 WriteAuthorization attach.
*/
package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubmitToLedger_ModeA_RelaysCreditToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	// Mode A: a configured credit token is relayed as Bearer so the ledger
	// authenticates the forward (→ skip PoW, deduct a credit).
	rec := httptest.NewRecorder()
	submitToLedger(rec, &Dependencies{LedgerEndpoint: srv.URL, LedgerCreditToken: "tok-mode-a"}, []byte("x"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("Mode A: status = %d, want 202", rec.Code)
	}
	if gotAuth != "Bearer tok-mode-a" {
		t.Errorf("Mode A: ledger saw Authorization=%q, want %q", gotAuth, "Bearer tok-mode-a")
	}

	// Mode B: no token ⇒ no Authorization header (the entry carries its own PoW).
	gotAuth = "sentinel"
	rec = httptest.NewRecorder()
	submitToLedger(rec, &Dependencies{LedgerEndpoint: srv.URL}, []byte("x"))
	if gotAuth != "" {
		t.Errorf("Mode B: ledger saw Authorization=%q, want none", gotAuth)
	}
}
