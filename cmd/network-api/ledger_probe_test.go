package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/clearcompass-ai/judicial-network/api/config"
)

// FUNCTIONAL: the boot probe client must verify the ledger's privately-signed
// cert against the configured CA and connect with NO client cert (the open-HTTPS
// posture). The regression this guards: probeLedgerReachable used a bare
// http.Client (system roots), which rejects the run CA over HTTPS — so the JN
// exited at boot ("ledger not reachable") and never served /readyz.
func TestLedgerProbeClient_ServerVerifyReachesPrivateLedger(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	// Open HTTPS: CA pinned, no client cert (API_LEDGER_ALLOW_SELF_SIGNED posture).
	c, err := ledgerProbeClient(config.Operational{LedgerEndpoint: srv.URL, LedgerCAFile: caFile})
	if err != nil {
		t.Fatalf("ledgerProbeClient: %v", err)
	}
	resp, err := c.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("probe GET failed — CA not honored? %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("probe status = %d, want 200", resp.StatusCode)
	}

	// The OLD probe behaviour (bare client, system roots) MUST be rejected by the
	// privately-signed cert — proves the CA pin is what makes the probe work.
	if _, err := (&http.Client{}).Get(srv.URL + "/healthz"); err == nil {
		t.Fatal("a bare client accepted a privately-signed ledger — the boot-probe bug")
	}
}

// A plaintext (http) endpoint needs no TLS material — a plain client is returned.
func TestLedgerProbeClient_PlaintextEndpoint(t *testing.T) {
	c, err := ledgerProbeClient(config.Operational{LedgerEndpoint: "http://ledger:8080"})
	if err != nil {
		t.Fatalf("ledgerProbeClient: %v", err)
	}
	if c == nil {
		t.Fatal("nil client for plaintext endpoint")
	}
}

// https + a bad CA path is startup-fatal (surfaced, not silently ignored).
func TestLedgerProbeClient_BadCAFailsClosed(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ledgerProbeClient(config.Operational{LedgerEndpoint: "https://ledger:8080", LedgerCAFile: bad}); err == nil {
		t.Fatal("unparseable CA must error")
	}
}
