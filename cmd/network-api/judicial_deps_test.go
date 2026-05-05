/*
FILE PATH: cmd/network-api/judicial_deps_test.go

DESCRIPTION:

	Pins buildJudicialDeps:

	  1. With LedgerEndpoint empty, deps that need an ledger
	     (LogQueries, Fetcher, LeafReader, Resolver, SchemaResolver)
	     are nil; in-memory fallbacks (KeyStore, DelKeyStore,
	     ContentStore) are non-nil so dev mode boots cleanly.

	  2. With LedgerEndpoint set + Davidson registered, the
	     per-destination LogQueries map has one entry per registered
	     destination, the HTTP-backed Fetcher / LeafReader /
	     Resolver / SchemaResolver are non-nil, and ContentStore
	     flips from in-memory to HTTP-backed iff
	     ArtifactStoreEndpoint is set.

	  3. Witness maps are initialized empty (not nil) so handler
	     code can `len()` them without nil-checks.
*/
package main

import (
	"testing"

	"github.com/clearcompass-ai/attesta/storage"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"

	tndavidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
)

func freshRegistry(t *testing.T) *jurisdiction.Registry {
	t.Helper()
	reg := jurisdiction.NewRegistry()
	if err := reg.Register(tndavidson.MustBundle()); err != nil {
		t.Fatalf("register davidson: %v", err)
	}
	reg.Freeze()
	return reg
}

// ─────────────────────────────────────────────────────────────────────
// Empty-config (dev) path
// ─────────────────────────────────────────────────────────────────────

func TestBuildJudicialDeps_NoLedger_StillBoots(t *testing.T) {
	reg := freshRegistry(t)
	deps, err := buildJudicialDeps(config.Operational{}, reg)
	if err != nil {
		t.Fatalf("buildJudicialDeps: %v", err)
	}
	if deps.Registry == nil {
		t.Error("Registry MUST be set even with empty ledger endpoint")
	}
	if deps.LogQueries != nil {
		t.Errorf("LogQueries MUST be nil with empty LedgerEndpoint; got %v", deps.LogQueries)
	}
	if deps.Fetcher != nil {
		t.Error("Fetcher MUST be nil with empty LedgerEndpoint")
	}
	if deps.LeafReader != nil {
		t.Error("LeafReader MUST be nil with empty LedgerEndpoint")
	}
	if deps.Resolver != nil {
		t.Error("Resolver MUST be nil with empty LedgerEndpoint")
	}
	if deps.KeyStore == nil {
		t.Error("KeyStore (in-memory fallback) MUST be set")
	}
	if deps.DelKeyStore == nil {
		t.Error("DelKeyStore (in-memory fallback) MUST be set")
	}
	if deps.ContentStore == nil {
		t.Error("ContentStore (in-memory fallback) MUST be set")
	}
	if deps.Extractor == nil {
		t.Error("Extractor MUST be set (JN schemas registry, no upstream needed)")
	}
}

func TestBuildJudicialDeps_WitnessMapsInitialized(t *testing.T) {
	deps, err := buildJudicialDeps(config.Operational{}, freshRegistry(t))
	if err != nil {
		t.Fatalf("buildJudicialDeps: %v", err)
	}
	if deps.WitnessKeys == nil {
		t.Error("WitnessKeys MUST be initialized (empty map, not nil)")
	}
	if deps.WitnessQuorum == nil {
		t.Error("WitnessQuorum MUST be initialized (empty map, not nil)")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Ledger-endpoint configured path
// ─────────────────────────────────────────────────────────────────────

func TestBuildJudicialDeps_WithLedger_PerDestinationQueries(t *testing.T) {
	reg := freshRegistry(t)
	deps, err := buildJudicialDeps(config.Operational{
		LedgerEndpoint: "https://ledger.example",
	}, reg)
	if err != nil {
		t.Fatalf("buildJudicialDeps: %v", err)
	}
	if got, want := len(deps.LogQueries), reg.Len(); got != want {
		t.Errorf("LogQueries len = %d, want %d (one per registered destination)", got, want)
	}
	for _, did := range reg.ExchangeDIDs() {
		if _, ok := deps.LogQueries[did]; !ok {
			t.Errorf("LogQueries missing entry for %s", did)
		}
	}
	if deps.Fetcher == nil || deps.LeafReader == nil || deps.Resolver == nil {
		t.Error("Fetcher / LeafReader / Resolver MUST be wired with ledger endpoint")
	}
	if deps.SchemaResolver == nil {
		t.Error("SchemaResolver MUST be wired (shim acceptable; nil is not)")
	}
}

func TestBuildJudicialDeps_ContentStore_FlipsToHTTP(t *testing.T) {
	deps, err := buildJudicialDeps(config.Operational{
		LedgerEndpoint:        "https://ledger.example",
		ArtifactStoreEndpoint: "https://artifacts.example",
	}, freshRegistry(t))
	if err != nil {
		t.Fatalf("buildJudicialDeps: %v", err)
	}
	if deps.ContentStore == nil {
		t.Fatal("ContentStore MUST be set")
	}
	if _, ok := deps.ContentStore.(*storage.InMemoryContentStore); ok {
		t.Error("ContentStore MUST be HTTP-backed when ArtifactStoreEndpoint set; got InMemoryContentStore")
	}
}

func TestBuildJudicialDeps_ContentStore_DefaultsInMemory(t *testing.T) {
	deps, err := buildJudicialDeps(config.Operational{
		LedgerEndpoint: "https://ledger.example",
		// ArtifactStoreEndpoint deliberately empty
	}, freshRegistry(t))
	if err != nil {
		t.Fatalf("buildJudicialDeps: %v", err)
	}
	if _, ok := deps.ContentStore.(*storage.InMemoryContentStore); !ok {
		t.Errorf("ContentStore MUST default to InMemoryContentStore; got %T", deps.ContentStore)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Schema resolver shim — declines, doesn't panic
// ─────────────────────────────────────────────────────────────────────

func TestSchemaResolverShim_DeclinesCleanly(t *testing.T) {
	r := newSchemaResolverShim()
	if _, err := r.Resolve(types.LogPosition{}, nil); err == nil {
		t.Error("shim resolver MUST return an error (nil hides misconfig at runtime)")
	}
}
