//go:build e2e

// Phase 0 — Preflight & trust root (SCENARIOS.md). These gate the run: in
// strict mode a failure here means the stack isn't trustworthy to test.
package jn

import (
	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/internal/bootstrap"
)

// S0.1 — All components on BOTH networks are live: each ledger /
// aggregator / JN healthy + ready, with at least the primary auditor
// of each network up. The 2-network baseline lives or dies on both
// sides being green.
func TestS0_1_AllComponentsLive(t *testing.T) {
	s := harness.NewStack(t)

	for _, n := range s.AllNetworks() {
		s.RequireNetworkLedger(t, n)
		code, body, _ := n.Ledger.Health()
		harness.Eq(t, code, 200, "net "+n.Name+" ledger /healthz status")
		harness.Eq(t, body, "ok", "net "+n.Name+" ledger /healthz body")

		if len(n.Auditors) > 0 {
			ac, _, _ := n.Auditors[0].Ready()
			harness.Eq(t, ac, 200, "net "+n.Name+" auditor[0] /readyz status")
		}

		aggCode, _, _ := n.Aggregator.Ready()
		harness.Eq(t, aggCode, 200, "net "+n.Name+" aggregator /readyz status")

		jn := s.NetworkJN(t, n)
		jc, jb, jerr := jn.Health()
		harness.Truthy(t, jerr == nil, "net "+n.Name+" JN /healthz (mTLS) error: "+harness.ErrStr(jerr))
		harness.Eq(t, jc, 200, "net "+n.Name+" JN /healthz status (mTLS)")
		harness.Eq(t, jb, "ok", "net "+n.Name+" JN /healthz body")
	}
}

// S0.2 — Per-network bootstrap parses and carries the core fields every
// component keys off, for BOTH networks. (Full byte-identity across the
// ledger/auditor/JN container mounts — true T8 — needs container
// introspection; tracked as a follow-up. S0.3 cross-checks the ledger
// actually loaded this exchange_did.)
func TestS0_2_SharedTrustRoot(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireBootstrap(t)

	for _, n := range s.AllNetworks() {
		if n.Boot.ExchangeDID == "" {
			t.Errorf("net %s: bootstrap not loaded (path %s)", n.Name, n.Cfg.BootstrapPath)
			continue
		}
		harness.NonEmpty(t, n.Boot.ExchangeDID, "net "+n.Name+" bootstrap exchange_did")
		harness.NonEmpty(t, n.Boot.NetworkName, "net "+n.Name+" bootstrap network_name")
		harness.Truthy(t, len(n.Boot.GenesisWitnessSet) > 0,
			"net "+n.Name+" bootstrap genesis_witness_set empty")
	}
}

// S0.3 — Per-network topology agreement: each ledger's log DID matches
// its bootstrap's exchange_did. Catches a ledger pointed at the wrong
// network's bootstrap.
func TestS0_3_TopologyAgreement(t *testing.T) {
	s := harness.NewStack(t)

	for _, n := range s.AllNetworks() {
		s.RequireNetworkLedger(t, n)
		if n.Boot.ExchangeDID == "" {
			t.Skipf("net %s: bootstrap not loaded", n.Name)
			continue
		}
		info, code, err := n.Ledger.LogInfo()
		harness.Truthy(t, err == nil, "net "+n.Name+" /v1/log-info error: "+harness.ErrStr(err))
		harness.Eq(t, code, 200, "net "+n.Name+" /v1/log-info status")
		harness.Truthy(t, mapHasValue(info, n.Boot.ExchangeDID),
			"net "+n.Name+" ledger /v1/log-info does not reference bootstrap exchange_did "+n.Boot.ExchangeDID)
	}
}

// S0.4 — Genesis keys are secp256k1 on BOTH networks. Every genesis
// witness DID is a did:key:zQ3s…; 1 ≤ K ≤ N for each network.
func TestS0_4_GenesisKeysSecp256k1(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireBootstrap(t)

	for _, n := range s.AllNetworks() {
		if n.Boot.ExchangeDID == "" {
			t.Skipf("net %s: bootstrap not loaded", n.Name)
			continue
		}
		w := len(n.Boot.GenesisWitnessSet)
		harness.Truthy(t, w > 0, "net "+n.Name+" genesis_witness_set empty")
		for _, did := range n.Boot.GenesisWitnessSet {
			harness.Truthy(t, bootstrap.IsSecp256k1(did),
				"net "+n.Name+" non-secp256k1 genesis DID: "+did)
		}
		k := n.QuorumK()
		harness.Truthy(t, k >= 1 && k <= w,
			"net "+n.Name+" quorum K out of range (K="+harness.Itoa(k)+", N="+harness.Itoa(w)+")")
	}
}

// --- small local helpers (shared by phase files) ---
// (errStr / itoa now live in tests/harness, surfaced via compat.go)

// mapHasValue reports whether any (possibly nested) string value in m equals
// want — used to find a DID in an unknown-shaped /v1/log-info payload.
func mapHasValue(m map[string]any, want string) bool {
	for _, v := range m {
		switch t := v.(type) {
		case string:
			if t == want {
				return true
			}
		case map[string]any:
			if mapHasValue(t, want) {
				return true
			}
		case []any:
			for _, e := range t {
				if sv, ok := e.(string); ok && sv == want {
					return true
				}
				if mv, ok := e.(map[string]any); ok && mapHasValue(mv, want) {
					return true
				}
			}
		}
	}
	return false
}
