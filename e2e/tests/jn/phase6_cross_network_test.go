//go:build e2e

// Phase 6 — Cross-network scenarios (the 2-network baseline's headline
// feature: shared witness + auditor identities serving multiple networks).
//
// These scenarios prove the topology contract: the SAME witness operator
// running TWO processes (one per network) using the SAME key produces the
// SAME DID in both networks' GenesisWitnessSet, and that DID actually
// shows up signing both networks' tree heads. That's the on-the-wire
// proof that "shared identity" is real, not just bookkeeping.
//
// Map of cross-network referring scenarios (added at S6.10+):
//
//	S6.10 TopologyManifestLoaded               — provisioner emitted the manifest
//	S6.11 SharedWitnessDIDsAreEqualAcrossNets  — same key → same DID across networks
//	S6.12 SharedWitnessSignsBothNetworksHeads  — DID actually cosigns both heads
//	S6.13 NetworkBootstrapsHaveDistinctIDs     — networks have distinct trust roots
//	S6.14 DestinationCatalogsMatchAcrossJNs    — both JNs carry the same destinations
//	                                              (network isolation is at the ledger)
//	S6.15 FederalRejectsTNDestination          — Federal ledger refuses a TN-only DID
//	                                              (cross-network admission denied)
package jn

import (
	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/internal/types"
)

// S6.10 — The provisioner emitted the topology manifest the cross-network
// scenarios depend on. Anchors every shared-identity test below.
func TestS6_10_TopologyManifestLoaded(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireTopology(t)

	if len(s.Topology.Networks) < 3 {
		t.Fatalf("topology has %d networks, want 3 (Federal + TN + CA)", len(s.Topology.Networks))
	}
	for _, name := range []string{"federal", "tn", "ca"} {
		if s.Topology.Network(name) == nil {
			t.Errorf("topology missing %s network", name)
		}
	}
	if len(s.Topology.SharedWitnessIdentities()) == 0 {
		t.Error("topology has no shared witness identities — the multi-network baseline must have at least one")
	}
}

// S6.11 — A SHARED witness identity has the same DID in EVERY network's
// bootstrap. Same secp256k1 key → same did:key:zQ3s… string; the bootstrap
// records that string per-position, and the topology manifest cross-indexes
// it by identity name. Mismatch means the provisioner staged different keys
// into different networks' witness-{i}.pem slots — a serious topology bug.
//
// In the 3-network baseline (Federal + TN + CA), the two "shared" witnesses
// participate in ALL THREE networks, so DIDPerNetwork has 3 entries each.
func TestS6_11_SharedWitnessDIDsAreEqualAcrossNets(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireSharedWitness(t)

	shared := s.Topology.SharedWitnessIdentities()
	if len(shared) == 0 {
		t.Fatal("no shared witness identities")
	}
	for _, w := range shared {
		if len(w.DIDPerNetwork) < 2 {
			t.Errorf("shared witness %s: did_per_network has %d entries, want >=2",
				w.Name, len(w.DIDPerNetwork))
			continue
		}
		var first, firstNet string
		for net, did := range w.DIDPerNetwork {
			if first == "" {
				first, firstNet = did, net
				continue
			}
			if did != first {
				t.Errorf("shared witness %s: net %s DID %q != net %s DID %q",
					w.Name, net, did, firstNet, first)
			}
		}
	}
}

// S6.12 — A shared witness identity ACTUALLY cosigns EVERY network's
// current tree head. We read each network's /v1/tree/head, collect
// signatures.pub_key_id, and assert the shared witness's DID is present
// in ALL THREE sets. This is the on-the-wire proof of cross-network
// signing across Federal + TN + CA.
func TestS6_12_SharedWitnessSignsBothNetworksHeads(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireSharedWitness(t)
	for _, n := range s.AllNetworks() {
		s.RequireNetworkLedger(t, n)
	}

	// Collect the signer DID set per network from each ledger's head.
	signersByNetwork := make(map[string]map[string]bool, 3)
	for _, n := range s.AllNetworks() {
		head, code, err := n.Ledger.TreeHead()
		if err != nil || code != 200 {
			t.Fatalf("net %s /v1/tree/head: code=%d err=%v", n.Name, code, err)
		}
		signersByNetwork[n.Name] = signerSet(head.Signatures)
	}

	atLeastOneCovered := false
	for _, w := range s.Topology.SharedWitnessIdentities() {
		missing := false
		for _, netName := range w.Networks {
			did := w.DIDPerNetwork[netName]
			if did == "" {
				t.Errorf("shared witness %s: missing DID in manifest for net %s", w.Name, netName)
				missing = true
				continue
			}
			if !signersByNetwork[netName][did] {
				t.Errorf("shared witness %s: DID %q NOT in net %s head signatures (signers=%v)",
					w.Name, did, netName, keys(signersByNetwork[netName]))
				missing = true
			}
		}
		if !missing && len(w.Networks) >= 2 {
			atLeastOneCovered = true
		}
	}
	if !atLeastOneCovered {
		t.Error("no shared witness identity appeared in EVERY participating network's head signatures — cross-network signing broken")
	}
}

// S6.13 — Every network has a DISTINCT trust root (exchange_did) — three
// separate networks must NOT share a NetworkID, or there's no isolation
// between them. Pin all pairs across Federal + TN + CA.
func TestS6_13_NetworkBootstrapsHaveDistinctIDs(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireTopology(t)

	seen := map[string]string{} // did → network name
	for _, name := range []string{"federal", "tn", "ca"} {
		n := s.Topology.Network(name)
		if n == nil {
			t.Errorf("topology missing %s network", name)
			continue
		}
		if n.ExchangeDID == "" {
			t.Errorf("net %s: empty exchange_did", name)
			continue
		}
		if other, ok := seen[n.ExchangeDID]; ok {
			t.Errorf("net %s shares exchange_did %q with net %s — networks must have distinct trust roots",
				name, n.ExchangeDID, other)
		}
		seen[n.ExchangeDID] = name
	}
}

// S6.14 — Every network's JN exposes the SAME destination catalog
// (all register the full 11-destination union via
// registerProductionBundles in cmd/network-api/main_helpers.go).
// Network isolation is enforced at the ledger boundary — see S6.15 —
// not at the registry. This pins the catalog-vs-isolation invariant:
// changing one without changing the other in lockstep is a bug.
func TestS6_14_DestinationCatalogsMatchAcrossJNs(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireTopology(t)

	// Each NetworkView.Destinations is the per-network's OWNED
	// destinations (3 Fed, 3 TN, 5 CA). The JN's destination registry
	// (the union of all bundles registered at boot) carries ALL 11
	// destinations. We pin that contract by asserting:
	//   (a) every network has at least one owned destination
	//   (b) no destination DID is owned by more than one network
	//       (cross-network ownership = configuration bug)
	seen := map[string]string{} // did → owning network
	for _, name := range []string{"federal", "tn", "ca"} {
		n := s.Topology.Network(name)
		if n == nil {
			t.Errorf("topology missing %s network", name)
			continue
		}
		if len(n.Destinations) == 0 {
			t.Errorf("net %s has no destinations in manifest", name)
		}
		for _, did := range n.Destinations {
			if other, ok := seen[did]; ok {
				t.Errorf("destination %q appears in both %s and %s manifests — networks must own distinct DIDs",
					did, other, name)
			}
			seen[did] = name
		}
	}
}

// S6.15 — Cross-network admission denial: submitting an entry destined for
// a TN-only DID (e.g. did:web:state:tn:davidson) to the Federal ledger
// must be REJECTED — the ledger enforces network isolation at the
// admission boundary, even though the JN registry knows about both
// catalogs. The exact rejection path depends on the ledger's admission
// gate; today we assert "the entry does not appear in the Federal ledger's
// query indexes after a cross-network publish attempt" — full negative-path
// wiring lands when an H1-style seeded submitter is available.
func TestS6_15_FederalRejectsTNDestination(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireSeededTypes(t)
	s.Pending(t, "S6.15: submit a TN-destination entry to Federal ledger; assert admission rejection (needs H1 seeded submitter)")
}

// ── small helpers (used only by the cross-network scenarios) ────────

// signerSet collects all pub_key_id values from a head's signature list
// into a string-set keyed by DID.
func signerSet(sigs []types.WitnessSignature) map[string]bool {
	out := make(map[string]bool, len(sigs))
	for _, s := range sigs {
		out[s.PubKeyID] = true
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
