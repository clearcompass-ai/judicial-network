package stack

import (
	"strings"
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/topology"
)

// testNetInfra builds a resolved single-network NetConfig + Infra for the pure
// env/arg builders. LogDID is filled the way the builder fills it after fixtures.
func testNetInfra(t *testing.T) (NetConfig, Infra) {
	t.Helper()
	spec, err := topology.Get("single")
	if err != nil {
		t.Fatalf("preset: %v", err)
	}
	nc := DeriveNetConfigs(spec, "a3f")[0]
	nc.LogDID = "did:web:baseproof:test-log"
	return nc, Infra{prefix: "baseproof-a3f", network: "baseproof-a3f"}
}

// ── cert SAN ───────────────────────────────────────────────────────────────

func TestServerSAN_CoversHostAndLedgerNames(t *testing.T) {
	san := serverSAN([]string{"baseproof-a3f-ledger"})
	for _, want := range []string{"DNS:localhost", "IP:127.0.0.1", "DNS:baseproof-a3f-ledger"} {
		if !strings.Contains(san, want) {
			t.Errorf("serverSAN missing %q\n  got: %s", want, san)
		}
	}
}

func TestServerSAN_MultiNetworkCoversEvery(t *testing.T) {
	names := []string{"baseproof-m7c-federal-ledger", "baseproof-m7c-tn-ledger", "baseproof-m7c-ca-ledger"}
	san := serverSAN(names)
	for _, n := range names {
		if !strings.Contains(san, "DNS:"+n) {
			t.Errorf("serverSAN missing DNS:%s\n  got: %s", n, san)
		}
	}
	// Regression: only the passed names are covered. The localhost-only SAN bug
	// let in-network handshakes fail server-name verification against the ledger.
	if strings.Contains(san, "absent-ledger") {
		t.Error("serverSAN covered a name that was never passed")
	}
}

func TestServerSAN_EmptyKeepsHostNamesOnly(t *testing.T) {
	if san := serverSAN(nil); san != "DNS:localhost,IP:127.0.0.1" {
		t.Fatalf("empty serverSAN = %q, want host names only", san)
	}
}

// ── ledger listener: terminates mTLS in-binary ───────────────────────────────

func TestLedgerBaseEnv_TerminatesMTLS(t *testing.T) {
	nc, in := testNetInfra(t)
	env := ledgerBaseEnv(nc, in)
	for k, want := range map[string]string{
		"LEDGER_TLS_CERT_FILE":          mntCerts + "/server.crt",
		"LEDGER_TLS_KEY_FILE":           mntCerts + "/server.key",
		"LEDGER_INBOUND_CLIENT_CA_FILE": mntCerts + "/ca.crt",
	} {
		if env[k] != want {
			t.Errorf("ledgerBaseEnv[%s] = %q, want %q", k, env[k], want)
		}
	}
	// LEDGER_INBOUND_CLIENT_CA_FILE is mandatory the moment LEDGER_TLS_CERT_FILE
	// is set (all-or-nothing) — both present together or the edge half-opens.
	if (env["LEDGER_TLS_CERT_FILE"] == "") != (env["LEDGER_INBOUND_CLIENT_CA_FILE"] == "") {
		t.Error("ledger TLS cert + inbound client CA must be set together")
	}
}

// ── auditor → ledger: pulls over the mTLS edge ──────────────────────────────

func TestAuditorEnv_PullsLedgerOverMTLS(t *testing.T) {
	nc, in := testNetInfra(t)
	env := auditorEnv(nc, in, 1)
	wantPeer := nc.LogDID + "=https://" + nc.Name("ledger") + ":8080"
	if env["AUDITOR_PEERS"] != wantPeer {
		t.Errorf("AUDITOR_PEERS = %q, want %q", env["AUDITOR_PEERS"], wantPeer)
	}
	// Regression: the pre-mTLS peer URL was plain http — must never recur.
	if strings.Contains(env["AUDITOR_PEERS"], "http://") {
		t.Errorf("AUDITOR_PEERS speaks plaintext http to the ledger: %q", env["AUDITOR_PEERS"])
	}
	for k, want := range map[string]string{
		"AUDITOR_PEER_CLIENT_CERT_FILE": mntCerts + "/client.crt",
		"AUDITOR_PEER_CLIENT_KEY_FILE":  mntCerts + "/client.key",
		"AUDITOR_PEER_CA_FILE":          mntCerts + "/ca.crt",
	} {
		if env[k] != want {
			t.Errorf("auditorEnv[%s] = %q, want %q", k, env[k], want)
		}
	}
}

// ── JN → ledger: reaches over the mTLS edge ─────────────────────────────────

func TestJNEnv_ReachesLedgerOverMTLS(t *testing.T) {
	nc, _ := testNetInfra(t)
	env := jnEnv(nc)
	if want := "https://" + nc.Name("ledger") + ":8080"; env["API_LEDGER_ENDPOINT"] != want {
		t.Errorf("API_LEDGER_ENDPOINT = %q, want %q", env["API_LEDGER_ENDPOINT"], want)
	}
	if strings.HasPrefix(env["API_LEDGER_ENDPOINT"], "http://") {
		t.Errorf("API_LEDGER_ENDPOINT speaks plaintext http to the ledger: %q", env["API_LEDGER_ENDPOINT"])
	}
	for k, want := range map[string]string{
		"API_LEDGER_CERT_FILE": mntCerts + "/client.crt",
		"API_LEDGER_KEY_FILE":  mntCerts + "/client.key",
		"API_LEDGER_CA_FILE":   mntCerts + "/ca.crt",
	} {
		if env[k] != want {
			t.Errorf("jnEnv[%s] = %q, want %q", k, env[k], want)
		}
	}
	// The gossip-ingest peer is the auditor's plain-http feed (not the ledger), so
	// it correctly stays http — guards against over-converting the wrong hop.
	if !strings.HasPrefix(env["API_GOSSIP_INGEST_PEER_URL"], "http://") {
		t.Errorf("gossip ingest peer should stay http (auditor feed): %q", env["API_GOSSIP_INGEST_PEER_URL"])
	}
}

// ── client tools (submit-stamp / backfill / audit) ──────────────────────────

func TestTLSArgs_ToolFlags(t *testing.T) {
	want := "-ca-cert " + mntCerts + "/ca.crt -client-cert " + mntCerts + "/client.crt -client-key " + mntCerts + "/client.key"
	if got := strings.Join(tlsArgs(), " "); got != want {
		t.Fatalf("tlsArgs = %q, want %q", got, want)
	}
}

func TestInnerURL_HTTPSAndCertsDir(t *testing.T) {
	nc, _ := testNetInfra(t)
	tg := nc.target("/fix", "/certs")
	if want := "https://" + nc.Name("ledger") + ":8080"; tg.innerURL() != want {
		t.Fatalf("innerURL = %q, want %q", tg.innerURL(), want)
	}
	if tg.CertsDir != "/certs" {
		t.Fatalf("target CertsDir = %q, want /certs", tg.CertsDir)
	}
}

// witnessEndpoints stays plain http by design (the cosign hop is trust-by-
// secp256k1-signature, not TLS) — assert it so a future "TLS everything" sweep
// is a deliberate decision, not an accident.
func TestWitnessEndpoints_StayHTTP(t *testing.T) {
	nc, _ := testNetInfra(t)
	if eps := witnessEndpoints(nc); !strings.HasPrefix(eps, "http://") || strings.Contains(eps, "https://") {
		t.Fatalf("witness endpoints should be plain http (cosign hop): %q", eps)
	}
}
