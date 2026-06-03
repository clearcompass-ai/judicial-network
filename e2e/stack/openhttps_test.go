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
// The server cert SAN must still cover every ledger container name: open HTTPS
// is server-authenticated (the caller verifies the ledger's cert), so a missing
// SAN breaks server-name verification just as it did under mTLS.

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
	if strings.Contains(san, "absent-ledger") {
		t.Error("serverSAN covered a name that was never passed")
	}
}

func TestServerSAN_EmptyKeepsHostNamesOnly(t *testing.T) {
	if san := serverSAN(nil); san != "DNS:localhost,IP:127.0.0.1" {
		t.Fatalf("empty serverSAN = %q, want host names only", san)
	}
}

// ── ledger listener: OPEN HTTPS (server-TLS, no inbound client CA) ───────────

func TestLedgerBaseEnv_OpenHTTPS(t *testing.T) {
	nc, in := testNetInfra(t)
	env := ledgerBaseEnv(nc, in)
	for k, want := range map[string]string{
		"LEDGER_TLS_CERT_FILE": mntCerts + "/server.crt",
		"LEDGER_TLS_KEY_FILE":  mntCerts + "/server.key",
	} {
		if env[k] != want {
			t.Errorf("ledgerBaseEnv[%s] = %q, want %q", k, env[k], want)
		}
	}
	// Open HTTPS: the ledger serves server-TLS but sets NO inbound client CA, so
	// the listener does not request a client cert (reads open; writes gated by
	// in-body crypto). Re-introducing it would re-close the edge.
	if _, ok := env["LEDGER_INBOUND_CLIENT_CA_FILE"]; ok {
		t.Error("ledgerBaseEnv still sets LEDGER_INBOUND_CLIENT_CA_FILE — that re-closes the open-HTTPS edge")
	}
}

// ── auditor → ledger: pulls over OPEN HTTPS (server-verify, no client cert) ──

func TestAuditorEnv_PullsLedgerOverOpenHTTPS(t *testing.T) {
	nc, in := testNetInfra(t)
	env := auditorEnv(nc, in, 1)
	wantPeer := nc.LogDID + "=https://" + nc.Name("ledger") + ":8080"
	if env["AUDITOR_PEERS"] != wantPeer {
		t.Errorf("AUDITOR_PEERS = %q, want %q", env["AUDITOR_PEERS"], wantPeer)
	}
	if strings.Contains(env["AUDITOR_PEERS"], "http://") {
		t.Errorf("AUDITOR_PEERS speaks plaintext http to the ledger: %q", env["AUDITOR_PEERS"])
	}
	for k, want := range map[string]string{
		"AUDITOR_PEER_CA_FILE":           mntCerts + "/ca.crt",
		"AUDITOR_PEER_ALLOW_SELF_SIGNED": "true",
	} {
		if env[k] != want {
			t.Errorf("auditorEnv[%s] = %q, want %q", k, env[k], want)
		}
	}
	for _, k := range []string{"AUDITOR_PEER_CLIENT_CERT_FILE", "AUDITOR_PEER_CLIENT_KEY_FILE"} {
		if _, ok := env[k]; ok {
			t.Errorf("auditorEnv still sets %s — open HTTPS presents no client cert", k)
		}
	}
}

// ── JN → ledger: reaches over OPEN HTTPS; JN's OWN listener stays mTLS ───────

func TestJNEnv_ReachesLedgerOverOpenHTTPS(t *testing.T) {
	nc, _ := testNetInfra(t)
	env := jnEnv(nc)
	if want := "https://" + nc.Name("ledger") + ":8080"; env["API_LEDGER_ENDPOINT"] != want {
		t.Errorf("API_LEDGER_ENDPOINT = %q, want %q", env["API_LEDGER_ENDPOINT"], want)
	}
	if strings.HasPrefix(env["API_LEDGER_ENDPOINT"], "http://") {
		t.Errorf("API_LEDGER_ENDPOINT speaks plaintext http to the ledger: %q", env["API_LEDGER_ENDPOINT"])
	}
	for k, want := range map[string]string{
		"API_LEDGER_CA_FILE":           mntCerts + "/ca.crt",
		"API_LEDGER_ALLOW_SELF_SIGNED": "true",
	} {
		if env[k] != want {
			t.Errorf("jnEnv[%s] = %q, want %q", k, env[k], want)
		}
	}
	// Open HTTPS to the ledger presents NO client cert.
	for _, k := range []string{"API_LEDGER_CERT_FILE", "API_LEDGER_KEY_FILE"} {
		if _, ok := env[k]; ok {
			t.Errorf("jnEnv still sets %s — the JN→ledger leg is open HTTPS (no client cert)", k)
		}
	}
	// The JN's OWN listener stays mTLS (it is the write gate, authenticating its
	// callers) — server cert/key + the client CA it verifies callers against.
	for k, want := range map[string]string{
		"API_AUTH_TLS_CERT_FILE":  mntCerts + "/server.crt",
		"API_AUTH_TLS_KEY_FILE":   mntCerts + "/server.key",
		"API_AUTH_CLIENT_CA_FILE": mntCerts + "/ca.crt",
	} {
		if env[k] != want {
			t.Errorf("jnEnv[%s] = %q, want %q (JN listener stays mTLS)", k, env[k], want)
		}
	}
	// The gossip-ingest peer is the auditor's plain-http feed (not the ledger).
	if !strings.HasPrefix(env["API_GOSSIP_INGEST_PEER_URL"], "http://") {
		t.Errorf("gossip ingest peer should stay http (auditor feed): %q", env["API_GOSSIP_INGEST_PEER_URL"])
	}
}

// ── client tools (submit-stamp / backfill / audit): open HTTPS, no client cert ──

func TestTLSArgs_OpenHTTPSToolFlags(t *testing.T) {
	want := "-ca-cert " + mntCerts + "/ca.crt -allow-self-signed"
	if got := strings.Join(tlsArgs(), " "); got != want {
		t.Fatalf("tlsArgs = %q, want %q", got, want)
	}
	// No client cert/key flags — open HTTPS.
	for _, flag := range tlsArgs() {
		if flag == "-client-cert" || flag == "-client-key" {
			t.Fatalf("tlsArgs still passes %q — open HTTPS presents no client cert", flag)
		}
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
