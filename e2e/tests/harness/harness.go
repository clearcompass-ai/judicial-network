//go:build e2e

package harness

import (
	"strings"
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/internal/bootstrap"
	"github.com/clearcompass-ai/judicial-network/e2e/internal/clients"
	"github.com/clearcompass-ai/judicial-network/e2e/internal/env"
	"github.com/clearcompass-ai/judicial-network/e2e/internal/httpx"
	"github.com/clearcompass-ai/judicial-network/e2e/internal/topology"
	"github.com/clearcompass-ai/judicial-network/e2e/internal/types"
)

// Stack is the resolved 3-network federation under test: per-network
// stacks (Federal + TN + CA), the shared topology manifest (which carries
// the cross-network identity linkage), and convenience aliases to the
// primary (Federal) network so existing single-network phase tests
// don't need a per-network rewrite.
//
// Cross-network scenarios (Phase 6 cross-component flows, the new
// shared-identity scenarios) walk s.Federal AND s.TN AND s.CA explicitly,
// or via s.AllNetworks(), and consult s.Topology for the identity-to-DID
// linkage.
type Stack struct {
	Cfg      env.Config
	Topology topology.Manifest

	// Per-network views — independent and all populated.
	Federal *NetworkStack
	TN      *NetworkStack
	CA      *NetworkStack

	// Federal-aliased convenience accessors. Existing single-network
	// phase tests (Phase 1 ledger, Phase 2 witness, Phase 4 aggregator,
	// Phase 5 JN) operate against the primary network by convention,
	// which is Federal in the multi-network baseline.
	Ledger     *clients.Ledger
	Witnesses  []*clients.Witness
	Auditor    *clients.Auditor // = Federal.Auditors[0]
	Aggregator *clients.Aggregator
	Boot       types.BootstrapDocument
}

// AllNetworks returns Federal + TN + CA so phase tests that want to
// iterate every network (S0.1, S0.2, S0.4, the cross-network family)
// can do it without naming each one.
func (s *Stack) AllNetworks() []*NetworkStack {
	return []*NetworkStack{s.Federal, s.TN, s.CA}
}

// NetworkStack is one network's resolved client surface.
type NetworkStack struct {
	Name       string
	Cfg        env.NetworkConfig
	Boot       types.BootstrapDocument
	Ledger     *clients.Ledger
	Witnesses  []*clients.Witness
	Auditors   []*clients.Auditor
	Aggregator *clients.Aggregator

	jn    *clients.JN
	jnErr error
}

// NewStack resolves env + topology + clients. It does NOT require every
// tier to be up; each scenario gates on what it needs.
func NewStack(t *testing.T) *Stack {
	t.Helper()
	cfg := env.Load()
	topo, _ := topology.Load(cfg.TopologyPath)
	s := &Stack{
		Cfg:      cfg,
		Topology: topo,
		Federal:  newNetworkStack(cfg.Federal, cfg.CACert, cfg.ClientCert, cfg.ClientKey),
		TN:       newNetworkStack(cfg.TN, cfg.CACert, cfg.ClientCert, cfg.ClientKey),
		CA:       newNetworkStack(cfg.CA, cfg.CACert, cfg.ClientCert, cfg.ClientKey),
	}
	// Federal-aliased convenience accessors.
	s.Ledger = s.Federal.Ledger
	s.Witnesses = s.Federal.Witnesses
	s.Aggregator = s.Federal.Aggregator
	s.Boot = s.Federal.Boot
	if len(s.Federal.Auditors) > 0 {
		s.Auditor = s.Federal.Auditors[0]
	}
	return s
}

func newNetworkStack(nc env.NetworkConfig, caCert, clientCert, clientKey string) *NetworkStack {
	ns := &NetworkStack{
		Name:       nc.Name,
		Cfg:        nc,
		Ledger:     newLedgerClient(nc.LedgerURL, caCert, clientCert, clientKey),
		Aggregator: clients.NewAggregator(nc.AggregatorURL),
	}
	for _, u := range nc.WitnessURLs {
		ns.Witnesses = append(ns.Witnesses, clients.NewWitness(u))
	}
	for _, u := range nc.AuditorURLs {
		ns.Auditors = append(ns.Auditors, clients.NewAuditor(u))
	}
	if boot, err := bootstrap.Load(nc.BootstrapPath); err == nil {
		ns.Boot = boot
	}
	ns.jn, ns.jnErr = clients.NewJN(nc.JNURL, caCert, clientCert, clientKey)
	return ns
}

// newLedgerClient builds the ledger client for nc.LedgerURL. The e2e ledger
// edge is mTLS, so an https URL gets a client that presents the run's client
// cert (the ledger sets LEDGER_INBOUND_CLIENT_CA_FILE and refuses plaintext);
// an http URL stays plain (a custom non-mTLS stack pointed at via
// E2E_*_LEDGER_URL). On a cert-load error it falls back to a plain client so
// the Stack still constructs — RequireLedger then surfaces the handshake
// failure as a clear "ledger not healthy" gate rather than a nil deref.
func newLedgerClient(url, caCert, clientCert, clientKey string) *clients.Ledger {
	if strings.HasPrefix(url, "https://") {
		if l, err := clients.NewLedgerMTLS(url, caCert, clientCert, clientKey); err == nil {
			return l
		}
	}
	return clients.NewLedger(url)
}

// QuorumK reports this network's configured K (with a sensible fallback
// when unset: full witness count, then 1).
func (n *NetworkStack) QuorumK() int {
	if n.Cfg.QuorumK > 0 {
		return n.Cfg.QuorumK
	}
	if w := len(n.Witnesses); w > 0 {
		return w
	}
	return 1
}

// QuorumK on the top-level Stack is the Federal network's K — the
// "primary" by convention.
func (s *Stack) QuorumK() int {
	return s.Federal.QuorumK()
}

// ─────────────────────────────────────────────────────────────────────
// Gates — REACHABILITY checks. In strict mode a missing dependency is
// a hard failure (the Stack is broken); otherwise it's a skip so a bare
// `go test` is clean without a Stack.
// ─────────────────────────────────────────────────────────────────────

func (s *Stack) Gate(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if ok {
		return
	}
	if s.Cfg.Strict {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// Pending is for a PREREQUISITE that isn't provisioned yet (H1–H5) — it
// ALWAYS skips even in strict mode because it's a known, tracked gap
// (SCENARIOS.md), not a Stack regression.
func (s *Stack) Pending(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Skipf("PENDING — "+format, args...)
}

// RequireLedger gates on the PRIMARY (Federal) ledger.
func (s *Stack) RequireLedger(t *testing.T) { s.RequireNetworkLedger(t, s.Federal) }

// RequireNetworkLedger gates on the named network's ledger.
func (s *Stack) RequireNetworkLedger(t *testing.T, n *NetworkStack) {
	t.Helper()
	code, _, err := n.Ledger.Health()
	s.Gate(t, err == nil && code == 200,
		"net %s: ledger %s not healthy: code=%d err=%v",
		n.Name, n.Cfg.LedgerURL, code, err)
}

// RequireAuditor gates on the PRIMARY (Federal)'s first auditor.
func (s *Stack) RequireAuditor(t *testing.T) {
	t.Helper()
	if s.Auditor == nil {
		s.Gate(t, false, "no Federal auditor configured")
		return
	}
	code, _, err := s.Auditor.Health()
	s.Gate(t, err == nil && code == 200, "Federal auditor not healthy: code=%d err=%v", code, err)
}

// RequireAggregator gates on the PRIMARY (Federal) aggregator.
func (s *Stack) RequireAggregator(t *testing.T) {
	t.Helper()
	code, _, err := s.Federal.Aggregator.Health()
	s.Gate(t, err == nil && code == 200,
		"Federal aggregator %s not healthy: code=%d err=%v",
		s.Federal.Cfg.AggregatorURL, code, err)
}

// RequireWitnesses gates on the PRIMARY (Federal) having reachable
// witness endpoints. Config alone isn't enough — defaults populate URLs
// even when no Stack is up, so a bare `go test` would fail at HTTP
// without a probe. We probe witness #0's /healthz and skip (or fatal
// in strict mode) on unreachable.
func (s *Stack) RequireWitnesses(t *testing.T) {
	t.Helper()
	s.Gate(t, len(s.Federal.Witnesses) > 0,
		"no Federal witness endpoints configured (set E2E_FEDERAL_WITNESS_URLS)")
	code, _, err := s.Federal.Witnesses[0].Health()
	s.Gate(t, err == nil && code == 200,
		"Federal witness #0 not healthy: code=%d err=%v", code, err)
}

// RequireBootstrap gates on the PRIMARY (Federal) bootstrap loading.
func (s *Stack) RequireBootstrap(t *testing.T) {
	t.Helper()
	s.Gate(t, s.Federal.Boot.ExchangeDID != "",
		"Federal bootstrap not loaded from %s", s.Federal.Cfg.BootstrapPath)
}

// RequireTopology gates on the manifest being loaded — the seam
// every shared-identity scenario gates on.
func (s *Stack) RequireTopology(t *testing.T) {
	t.Helper()
	s.Gate(t, s.Topology.Loaded(),
		"topology manifest not loaded from %s (provisioner emits it at the end of `make up`)",
		s.Cfg.TopologyPath)
}

// JN returns the PRIMARY (Federal) mTLS enforcer client.
func (s *Stack) JN(t *testing.T) *clients.JN {
	t.Helper()
	s.Gate(t, s.Federal.jnErr == nil,
		"Federal JN mTLS client unavailable (certs under %s): %v",
		s.Cfg.CACert, s.Federal.jnErr)
	return s.Federal.jn
}

// FederalJN / TNJN / CAJN are the explicit per-network JN accessors for
// cross-network scenarios.
func (s *Stack) FederalJN(t *testing.T) *clients.JN { return s.NetworkJN(t, s.Federal) }
func (s *Stack) TNJN(t *testing.T) *clients.JN      { return s.NetworkJN(t, s.TN) }
func (s *Stack) CAJN(t *testing.T) *clients.JN      { return s.NetworkJN(t, s.CA) }

func (s *Stack) NetworkJN(t *testing.T, n *NetworkStack) *clients.JN {
	t.Helper()
	s.Gate(t, n.jnErr == nil,
		"net %s: JN mTLS client unavailable (certs under %s): %v",
		n.Name, s.Cfg.CACert, n.jnErr)
	return n.jn
}

// JNNoCert returns a client that trusts the JN's CA but presents NO
// client cert — to prove the enforcer rejects an unauthenticated
// caller (S5.1, S7.8). Points at the PRIMARY (Federal) JN.
func (s *Stack) JNNoCert(t *testing.T) *httpx.Client {
	t.Helper()
	c, err := httpx.NewServerTrust(s.Federal.Cfg.JNURL, s.Cfg.CACert)
	s.Gate(t, err == nil, "Federal JN server-trust client unavailable (CA %s): %v", s.Cfg.CACert, err)
	return c
}

// RequireSecondCourt gates on the TN network being up — fulfilling
// prerequisite H2 in SCENARIOS.md. In the multi-network baseline this
// is always provisioned; the gate exists so a future single-network
// override still skips cleanly.
func (s *Stack) RequireSecondCourt(t *testing.T) {
	t.Helper()
	if s.TN == nil {
		s.Pending(t, "H2: TN network not configured")
		return
	}
	code, _, err := s.TN.Ledger.Health()
	s.Gate(t, err == nil && code == 200,
		"H2: TN ledger %s not healthy: code=%d err=%v",
		s.TN.Cfg.LedgerURL, code, err)
}

// RequireThirdCourt gates on the California network being up — the
// 3rd-network family of scenarios depends on it. Mirrors
// RequireSecondCourt for the TN view.
func (s *Stack) RequireThirdCourt(t *testing.T) {
	t.Helper()
	if s.CA == nil {
		s.Pending(t, "CA network not configured")
		return
	}
	code, _, err := s.CA.Ledger.Health()
	s.Gate(t, err == nil && code == 200,
		"CA ledger %s not healthy: code=%d err=%v",
		s.CA.Cfg.LedgerURL, code, err)
}

// RequireSharedWitness gates on at least one shared witness identity
// being present in the topology manifest — the prerequisite every
// cross-network referring scenario needs.
func (s *Stack) RequireSharedWitness(t *testing.T) {
	t.Helper()
	s.RequireTopology(t)
	if len(s.Topology.SharedWitnessIdentities()) == 0 {
		s.Gate(t, false, "no shared witness identities in topology manifest")
	}
}

// RequireSeededTypes gates on prerequisite H1 — varied judicial entry
// types + delegation chains seeded on the primary court log. Until a
// seeding fixture lands (E2E_H1_SEEDED), the per-type indexing +
// enforcement-gate scenarios pend.
func (s *Stack) RequireSeededTypes(t *testing.T) {
	t.Helper()
	if !s.Cfg.H1Seeded {
		s.Pending(t, "H1: varied entry types + delegations not seeded yet (set E2E_H1_SEEDED once the primary court log carries officers/cases/parties + a delegation chain)")
	}
}

// RequireForkFixture gates on a fork-injection fixture (prerequisite H4).
func (s *Stack) RequireForkFixture(t *testing.T) {
	t.Helper()
	if !s.Cfg.ForkEnabled {
		s.Pending(t, "H4: no fork-injection fixture (set E2E_FORK_ENABLE once a byzantine-witness/twin-ledger fixture exists)")
	}
}

// JNFamilyMounted POSTs {} to each candidate path on the PRIMARY JN
// and passes if any is mounted (status != 404).
func (s *Stack) JNFamilyMounted(t *testing.T, jn *clients.JN, family string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		code, _, err := jn.PostRaw(p, "application/json", []byte("{}"))
		if err != nil {
			continue
		}
		if code != 404 {
			SurfaceOK(t, code, p)
			return
		}
	}
	s.Pending(t, "%s: none of the candidate routes mounted (confirm paths): %s", family, strings.Join(paths, ", "))
}

// HeadSize returns the PRIMARY ledger's current tree size and whether
// a cosigned head exists.
func (s *Stack) HeadSize() (uint64, bool) {
	return s.Federal.HeadSize()
}

// HeadSize on a NetworkStack returns that network's tree size.
func (n *NetworkStack) HeadSize() (uint64, bool) {
	head, code, err := n.Ledger.TreeHead()
	if err != nil || code != 200 {
		return 0, false
	}
	return head.TreeSize, true
}
