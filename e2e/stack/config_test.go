package stack

import (
	"strings"
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/topology"
)

func TestDeriveNetConfigs_SingleCollapses(t *testing.T) {
	spec, _ := topology.Get("single")
	ncs := DeriveNetConfigs(spec, "a3f")
	if len(ncs) != 1 {
		t.Fatalf("got %d net configs, want 1", len(ncs))
	}
	c := ncs[0]
	if !c.Single {
		t.Fatal("single-network stack should mark Single")
	}
	if c.Prefix != "baseproof-a3f" {
		t.Fatalf("prefix = %q, want baseproof-a3f (no network segment for single)", c.Prefix)
	}
	if c.DB != "baseproof_test" {
		t.Fatalf("db = %q, want baseproof_test (the default POSTGRES_DB)", c.DB)
	}
	if c.Name("ledger") != "baseproof-a3f-ledger" {
		t.Fatalf("ledger name = %q", c.Name("ledger"))
	}
	if c.GossipDB(1) != "auditor_gossip_1" {
		t.Fatalf("single gossip db = %q, want auditor_gossip_1", c.GossipDB(1))
	}
	if c.LedgerPort != 8080 {
		t.Fatalf("ledger port = %d, want 8080", c.LedgerPort)
	}
}

func TestDeriveNetConfigs_FederationUniquePortsAndDBs(t *testing.T) {
	spec, _ := topology.Get("federation")
	ncs := DeriveNetConfigs(spec, "m7c")
	if len(ncs) != 3 {
		t.Fatalf("got %d net configs, want 3", len(ncs))
	}
	seenPort := map[int]bool{}
	seenDB := map[string]bool{}
	seenGossip := map[string]bool{}
	for _, c := range ncs {
		if c.Single {
			t.Fatalf("multi-network config %q should not be Single", c.Spec.Name)
		}
		if !strings.HasPrefix(c.Prefix, "baseproof-m7c-") {
			t.Fatalf("prefix %q missing network segment", c.Prefix)
		}
		if seenPort[c.LedgerPort] {
			t.Fatalf("duplicate ledger port %d", c.LedgerPort)
		}
		seenPort[c.LedgerPort] = true
		if seenDB[c.DB] {
			t.Fatalf("duplicate ledger DB %q across networks", c.DB)
		}
		seenDB[c.DB] = true
		// gossip DB names must be globally unique (shared postgres).
		for idx := 1; idx <= c.Spec.Auditors; idx++ {
			g := c.GossipDB(idx)
			if seenGossip[g] {
				t.Fatalf("duplicate gossip DB %q across the stack", g)
			}
			seenGossip[g] = true
		}
		// auditor host ports must be unique too.
		for _, p := range c.AuditorPorts {
			if seenPort[p] {
				t.Fatalf("auditor port %d collides", p)
			}
			seenPort[p] = true
		}
	}
}
