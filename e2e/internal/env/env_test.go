package env

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/runstore"
)

// overrideVars are every E2E_* knob Load consults. Derivation tests clear them so
// an ambient environment can't pollute the manifest-derived assertions; the
// override test sets them explicitly afterwards.
var overrideVars = func() []string {
	v := []string{"E2E_RUN_ROOT", "E2E_TOPOLOGY", "E2E_CA_CERT", "E2E_CLIENT_CERT", "E2E_CLIENT_KEY", "E2E_STRICT", "E2E_H1_SEEDED", "E2E_FORK_ENABLE"}
	for _, net := range []string{"FEDERAL", "TN", "CA"} {
		for _, s := range []string{"_LEDGER_URL", "_JN_URL", "_AGGREGATOR_URL", "_BOOTSTRAP", "_PG_CONTAINER", "_WITNESS_URLS", "_AUDITOR_URLS", "_QUORUM_K"} {
			v = append(v, "E2E_"+net+s)
		}
	}
	return v
}()

// provision writes a run under a fresh E2E_RUN_ROOT exactly as the real
// provisioner does (a stack.json manifest under {root}/{id}), with all E2E_*
// overrides cleared. A nil manifest provisions the run dir but no manifest.
func provision(t *testing.T, id string, m *runstore.Manifest) *runstore.Layout {
	t.Helper()
	for _, k := range overrideVars {
		t.Setenv(k, "")
	}
	root := t.TempDir()
	t.Setenv("E2E_RUN_ROOT", root)
	lay, err := runstore.NewUnder(root, id)
	if err != nil {
		t.Fatalf("NewUnder(%q): %v", id, err)
	}
	if m != nil {
		m.ID = id
		if err := lay.SaveManifest(m); err != nil {
			t.Fatalf("SaveManifest: %v", err)
		}
	} else if err := lay.Mkdirs(); err != nil {
		t.Fatalf("Mkdirs: %v", err)
	}
	return lay
}

func federationManifest() *runstore.Manifest {
	return &runstore.Manifest{
		Preset:  "federation",
		Network: "baseproof-abc",
		Networks: []runstore.NetworkManifest{
			{Name: "federal", QuorumK: 3, LedgerPort: 8080, JNPort: 8443, AggregatorPort: 8092, AuditorPorts: []int{8088, 8089, 8090}},
			{Name: "tn", QuorumK: 2, LedgerPort: 8100, JNPort: 8463, AggregatorPort: 8112, AuditorPorts: []int{8108}},
			{Name: "ca", QuorumK: 2, LedgerPort: 8120, JNPort: 8483, AggregatorPort: 8132, AuditorPorts: []int{8128}},
		},
	}
}

// TestLoad_Federation is the core objective: a provisioned 3-network federation
// must resolve into the exact addressable Config the harness consumes — service
// URLs with the right schemes from host ports, per-network bootstrap + Postgres
// container, quorum K, and the run's shared TLS material + topology path.
func TestLoad_Federation(t *testing.T) {
	lay := provision(t, "abc", federationManifest())
	cfg := Load()

	// Shared material is rooted in the run layout.
	for _, c := range []struct{ name, got, want string }{
		{"TopologyPath", cfg.TopologyPath, filepath.Join(lay.Home, "topology.json")},
		{"CACert", cfg.CACert, filepath.Join(lay.Certs, "ca.crt")},
		{"ClientCert", cfg.ClientCert, filepath.Join(lay.Certs, "client.crt")},
		{"ClientKey", cfg.ClientKey, filepath.Join(lay.Certs, "client.key")},
		{"PGContainer", cfg.PGContainer, "baseproof-abc-postgres"}, // shared per run
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}

	// Each network resolves to its full surface. ledger/JN are https; aggregator
	// and auditors are http (matching the plain typed clients).
	want := map[string]NetworkConfig{
		"federal": {
			Name: "federal", LedgerURL: "https://localhost:8080", JNURL: "https://localhost:8443",
			AggregatorURL: "http://localhost:8092",
			AuditorURLs:   []string{"http://localhost:8088", "http://localhost:8089", "http://localhost:8090"},
			BootstrapPath: filepath.Join(lay.Fixtures, "federal", "network-bootstrap.json"),
			QuorumK:       3,
		},
		"tn": {
			Name: "tn", LedgerURL: "https://localhost:8100", JNURL: "https://localhost:8463",
			AggregatorURL: "http://localhost:8112",
			AuditorURLs:   []string{"http://localhost:8108"},
			BootstrapPath: filepath.Join(lay.Fixtures, "tn", "network-bootstrap.json"),
			QuorumK:       2,
		},
		"ca": {
			Name: "ca", LedgerURL: "https://localhost:8120", JNURL: "https://localhost:8483",
			AggregatorURL: "http://localhost:8132",
			AuditorURLs:   []string{"http://localhost:8128"},
			BootstrapPath: filepath.Join(lay.Fixtures, "ca", "network-bootstrap.json"),
			QuorumK:       2,
		},
	}
	got := map[string]NetworkConfig{"federal": cfg.Federal, "tn": cfg.TN, "ca": cfg.CA}
	for name, w := range want {
		if !reflect.DeepEqual(got[name], w) {
			t.Errorf("%s network:\n got  %+v\n want %+v", name, got[name], w)
		}
	}

	// Witnesses are NOT in the manifest, so without an env override they're empty
	// (the harness then skips RequireWitnesses) — proving the documented contract.
	if len(cfg.Federal.WitnessURLs) != 0 {
		t.Errorf("Federal.WitnessURLs = %v, want empty (not carried in the manifest)", cfg.Federal.WitnessURLs)
	}
}

// TestLoad_EnvOverrides proves every override wins over the manifest-derived
// default, including comma-split witness/auditor lists (trimmed, blanks dropped).
func TestLoad_EnvOverrides(t *testing.T) {
	provision(t, "abc", federationManifest())
	t.Setenv("E2E_TOPOLOGY", "/custom/topology.json")
	t.Setenv("E2E_CA_CERT", "/custom/ca.pem")
	t.Setenv("E2E_STRICT", "true")
	t.Setenv("E2E_H1_SEEDED", "1")
	t.Setenv("E2E_FORK_ENABLE", "yes")
	t.Setenv("E2E_FEDERAL_LEDGER_URL", "http://ledger.local:9000")
	t.Setenv("E2E_FEDERAL_JN_URL", "http://jn.local:9001")
	t.Setenv("E2E_FEDERAL_AGGREGATOR_URL", "https://agg.local:9002")
	t.Setenv("E2E_PG_CONTAINER", "my-pg")
	t.Setenv("E2E_FEDERAL_QUORUM_K", "7")
	t.Setenv("E2E_FEDERAL_WITNESS_URLS", " http://w0:1 , http://w1:2 ,, ")
	t.Setenv("E2E_FEDERAL_AUDITOR_URLS", "http://aud:1")

	cfg := Load()

	checks := []struct{ name, got, want string }{
		{"TopologyPath", cfg.TopologyPath, "/custom/topology.json"},
		{"CACert", cfg.CACert, "/custom/ca.pem"},
		{"Federal.LedgerURL", cfg.Federal.LedgerURL, "http://ledger.local:9000"},
		{"Federal.JNURL", cfg.Federal.JNURL, "http://jn.local:9001"},
		{"Federal.AggregatorURL", cfg.Federal.AggregatorURL, "https://agg.local:9002"},
		{"PGContainer", cfg.PGContainer, "my-pg"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if !cfg.Strict || !cfg.H1Seeded || !cfg.ForkEnabled {
		t.Errorf("flags = {Strict:%v H1Seeded:%v ForkEnabled:%v}, want all true", cfg.Strict, cfg.H1Seeded, cfg.ForkEnabled)
	}
	if cfg.Federal.QuorumK != 7 {
		t.Errorf("Federal.QuorumK = %d, want 7 (override)", cfg.Federal.QuorumK)
	}
	if w := cfg.Federal.WitnessURLs; !reflect.DeepEqual(w, []string{"http://w0:1", "http://w1:2"}) {
		t.Errorf("Federal.WitnessURLs = %v, want [http://w0:1 http://w1:2] (trimmed, blanks dropped)", w)
	}
	if a := cfg.Federal.AuditorURLs; !reflect.DeepEqual(a, []string{"http://aud:1"}) {
		t.Errorf("Federal.AuditorURLs = %v, want [http://aud:1] (override replaces manifest)", a)
	}
}

// TestLoad_SingleNetwork proves a one-network preset surfaces as Federal (even
// when named otherwise) while TN/CA stay empty so their gates skip cleanly.
func TestLoad_SingleNetwork(t *testing.T) {
	provision(t, "xyz", &runstore.Manifest{
		Preset:  "throughput",
		Network: "baseproof-xyz",
		Networks: []runstore.NetworkManifest{
			{Name: "main", QuorumK: 1, LedgerPort: 8080, JNPort: 8443},
		},
	})
	cfg := Load()

	if cfg.Federal.Name != "main" || cfg.Federal.LedgerURL != "https://localhost:8080" || cfg.Federal.QuorumK != 1 {
		t.Errorf("single network did not surface as Federal: %+v", cfg.Federal)
	}
	if cfg.PGContainer != "baseproof-xyz-postgres" {
		t.Errorf("PGContainer = %q, want baseproof-xyz-postgres", cfg.PGContainer)
	}
	for _, n := range []NetworkConfig{cfg.TN, cfg.CA} {
		if n.LedgerURL != "" || len(n.AuditorURLs) != 0 {
			t.Errorf("absent network should have no endpoints, got %+v", n)
		}
	}
}

// TestLoad_NoRun proves a bare `go test` (no provisioned run) never panics and
// yields an empty-but-valid Config so every harness Gate skips — while env-only
// flags are still honored.
func TestLoad_NoRun(t *testing.T) {
	for _, k := range overrideVars {
		t.Setenv(k, "")
	}
	t.Setenv("E2E_RUN_ROOT", t.TempDir()) // empty root: no runs
	t.Setenv("E2E_H1_SEEDED", "true")

	cfg := Load() // must not panic

	if cfg.TopologyPath != "" || cfg.CACert != "" {
		t.Errorf("no run: expected empty TLS/topology paths, got topo=%q ca=%q", cfg.TopologyPath, cfg.CACert)
	}
	if cfg.Federal.LedgerURL != "" {
		t.Errorf("no run: expected empty Federal endpoints, got %+v", cfg.Federal)
	}
	if cfg.PGContainer != "" {
		t.Errorf("no run: expected empty PGContainer, got %q", cfg.PGContainer)
	}
	if cfg.Federal.Name != "federal" || cfg.TN.Name != "tn" || cfg.CA.Name != "ca" {
		t.Errorf("no run: networks should keep their default labels, got %q/%q/%q", cfg.Federal.Name, cfg.TN.Name, cfg.CA.Name)
	}
	if !cfg.H1Seeded {
		t.Error("no run: env-only flag E2E_H1_SEEDED should still be honored")
	}
}

// TestLoad_ManifestMissing proves a partially-provisioned run (layout present, no
// stack.json) still yields the run's TLS/topology paths while leaving endpoints
// empty — the provisioning-in-progress state degrades, it doesn't panic.
func TestLoad_ManifestMissing(t *testing.T) {
	lay := provision(t, "def", nil) // run dir, no manifest
	cfg := Load()

	if cfg.CACert != filepath.Join(lay.Certs, "ca.crt") {
		t.Errorf("CACert = %q, want it derived from the run layout", cfg.CACert)
	}
	if cfg.Federal.LedgerURL != "" {
		t.Errorf("Federal.LedgerURL = %q, want empty (no manifest)", cfg.Federal.LedgerURL)
	}
	if cfg.PGContainer != "baseproof-def-postgres" {
		t.Errorf("PGContainer = %q, want baseproof-def-postgres (from run id, independent of the manifest)", cfg.PGContainer)
	}
}

func TestHostURL(t *testing.T) {
	cases := []struct {
		scheme string
		port   int
		want   string
	}{
		{"https", 8080, "https://localhost:8080"},
		{"http", 8092, "http://localhost:8092"},
		{"https", 0, ""},  // unset port → no URL
		{"https", -1, ""}, // invalid port → no URL
	}
	for _, c := range cases {
		if got := hostURL(c.scheme, c.port); got != c.want {
			t.Errorf("hostURL(%q,%d) = %q, want %q", c.scheme, c.port, got, c.want)
		}
	}
}

func TestSplitList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b ", []string{"a", "b"}},
		{"a,,b, ,", []string{"a", "b"}},
		{"", nil},
		{" , ", nil},
	}
	for _, c := range cases {
		if got := splitList(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitList(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestEnvBool(t *testing.T) {
	truthy := []string{"1", "true", "TRUE", "Yes", "on"}
	falsy := []string{"", "0", "false", "no", "off", "nope"}
	for _, v := range truthy {
		t.Setenv("E2E_TEST_BOOL", v)
		if !envBool("E2E_TEST_BOOL") {
			t.Errorf("envBool(%q) = false, want true", v)
		}
	}
	for _, v := range falsy {
		t.Setenv("E2E_TEST_BOOL", v)
		if envBool("E2E_TEST_BOOL") {
			t.Errorf("envBool(%q) = true, want false", v)
		}
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("E2E_TEST_OR", "  value  ")
	if got := envOr("E2E_TEST_OR", "def"); got != "value" {
		t.Errorf("envOr(set) = %q, want trimmed %q", got, "value")
	}
	t.Setenv("E2E_TEST_OR", "   ")
	if got := envOr("E2E_TEST_OR", "def"); got != "def" {
		t.Errorf("envOr(blank) = %q, want default %q", got, "def")
	}
}
