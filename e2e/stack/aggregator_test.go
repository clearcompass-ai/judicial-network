package stack

import (
	"strings"
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/topology"
)

// The aggregator scans the ledger over the mTLS edge (v1.65.0 secure-by-default):
// https endpoint + the shared client cert. Plaintext here would fail-closed at the
// ledger and is a regression.
func TestAggregatorEnv_ScansLedgerOverMTLS(t *testing.T) {
	nc, in := testNetInfra(t) // single-network NetConfig (AggDB already derived)
	env := aggregatorEnv(nc, in)

	if want := "https://" + nc.Name("ledger") + ":8080"; env["TOOLS_LEDGER_URL"] != want {
		t.Errorf("TOOLS_LEDGER_URL = %q, want %q", env["TOOLS_LEDGER_URL"], want)
	}
	if strings.HasPrefix(env["TOOLS_LEDGER_URL"], "http://") {
		t.Errorf("aggregator scans the ledger in plaintext: %q", env["TOOLS_LEDGER_URL"])
	}
	for k, want := range map[string]string{
		"TOOLS_LEDGER_CLIENT_CERT_FILE": mntCerts + "/client.crt",
		"TOOLS_LEDGER_CLIENT_KEY_FILE":  mntCerts + "/client.key",
		"TOOLS_LEDGER_CA_FILE":          mntCerts + "/ca.crt",
	} {
		if env[k] != want {
			t.Errorf("aggregatorEnv[%s] = %q, want %q", k, env[k], want)
		}
	}
	for _, k := range []string{"TOOLS_OFFICERS_LOG", "TOOLS_CASES_LOG", "TOOLS_PARTIES_LOG"} {
		if env[k] != nc.LogDID {
			t.Errorf("aggregatorEnv[%s] = %q, want network log DID %q", k, env[k], nc.LogDID)
		}
	}
	if !strings.Contains(env["TOOLS_DATABASE_URL"], "aggregator") {
		t.Errorf("TOOLS_DATABASE_URL missing the aggregator projection DB: %q", env["TOOLS_DATABASE_URL"])
	}
}

// Federation: every HasAggregator network gets a distinct aggregator port (no
// collision with ledger/jn/auditor ports) and a distinct projection DB.
func TestDeriveNetConfigs_AggregatorPortsAndDBsDistinct(t *testing.T) {
	spec, _ := topology.Get("federation")
	ncs := DeriveNetConfigs(spec, "m7c")

	seenPort := map[int]bool{}
	for _, c := range ncs { // ledger/jn/auditor ports first
		seenPort[c.LedgerPort] = true
		seenPort[c.JNPort] = true
		for _, p := range c.AuditorPorts {
			seenPort[p] = true
		}
	}
	seenDB := map[string]bool{}
	for _, c := range ncs {
		if !c.Spec.HasAggregator {
			continue
		}
		if c.AggregatorPort == 0 {
			t.Errorf("net %s HasAggregator but AggregatorPort==0", c.Spec.Name)
		}
		if seenPort[c.AggregatorPort] {
			t.Errorf("net %s aggregator port %d collides with a ledger/jn/auditor port", c.Spec.Name, c.AggregatorPort)
		}
		seenPort[c.AggregatorPort] = true
		if seenDB[c.AggDB] {
			t.Errorf("duplicate aggregator DB %q across networks", c.AggDB)
		}
		seenDB[c.AggDB] = true
	}
}
