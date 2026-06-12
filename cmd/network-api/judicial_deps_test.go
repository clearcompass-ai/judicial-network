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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/storage"
	"github.com/baseproof/baseproof/types"

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

// ──────────────────────────────────────────────────────────────────
// Empty-config (dev) path
// ──────────────────────────────────────────────────────────────────

func TestBuildJudicialDeps_NoLedger_StillBoots(t *testing.T) {
	reg := freshRegistry(t)
	deps, err := buildJudicialDeps(config.Operational{}, reg, nil, nil)
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

func TestBuildJudicialDeps_EraResolverThreaded(t *testing.T) {
	// FED-1 #107: the static WitnessSets map is GONE; the resolver the
	// caller supplies is what deps carry — verbatim, no re-wrapping.
	deps, err := buildJudicialDeps(config.Operational{}, freshRegistry(t), nil, nil)
	if err != nil {
		t.Fatalf("buildJudicialDeps: %v", err)
	}
	if deps.Eras != nil {
		t.Error("a nil resolver must thread as nil (handlers fail closed), never be defaulted")
	}
}

// ──────────────────────────────────────────────────────────────────
// Ledger-endpoint configured path
// ──────────────────────────────────────────────────────────────────

func TestBuildJudicialDeps_WithLedger_PerDestinationQueries(t *testing.T) {
	reg := freshRegistry(t)
	deps, err := buildJudicialDeps(config.Operational{
		LedgerEndpoint: "https://ledger.example",
	}, reg, nil, nil)
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
	}, freshRegistry(t), nil, nil)
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
	}, freshRegistry(t), nil, nil)
	if err != nil {
		t.Fatalf("buildJudicialDeps: %v", err)
	}
	if _, ok := deps.ContentStore.(*storage.InMemoryContentStore); !ok {
		t.Errorf("ContentStore MUST default to InMemoryContentStore; got %T", deps.ContentStore)
	}
}

// ──────────────────────────────────────────────────────────────────
// Schema resolver shim — declines, doesn't panic
// ──────────────────────────────────────────────────────────────────

func TestSchemaResolverShim_DeclinesCleanly(t *testing.T) {
	r := newSchemaResolverShim()
	if _, err := r.Resolve(context.Background(), types.LogPosition{}, nil); err == nil {
		t.Error("shim resolver MUST return an error (nil hides misconfig at runtime)")
	}
}

// ──────────────────────────────────────────────────────────────────
// D2 — Auditor scope inputs threaded into deps
// ──────────────────────────────────────────────────────────────────

// Without a bootstrap file the authoritative resolver is nil, the
// AuditorScopeAsOf closure is nil, and the auditor record slices are
// nil — the legal pre-v1.33 posture.
func TestBuildJudicialDeps_NoBootstrap_ResolverNil(t *testing.T) {
	deps, err := buildJudicialDeps(config.Operational{}, freshRegistry(t), nil, nil)
	if err != nil {
		t.Fatalf("buildJudicialDeps: %v", err)
	}
	if deps.AuthoritativeResolver != nil {
		t.Error("AuthoritativeResolver MUST be nil when NetworkBootstrapFile is empty")
	}
	if deps.AuditorScopeAsOf != nil {
		t.Error("AuditorScopeAsOf MUST be nil when NetworkBootstrapFile is empty")
	}
	if deps.AuditorRegistry != nil {
		t.Errorf("AuditorRegistry MUST be nil with empty RegistryFile; got %v", deps.AuditorRegistry)
	}
	if deps.AuditorAmendments != nil {
		t.Errorf("AuditorAmendments MUST be nil with empty AmendmentFile; got %v", deps.AuditorAmendments)
	}
}

// File-loaded auditor registry threads cleanly through to deps.
func TestBuildJudicialDeps_LoadsAuditorRegistry(t *testing.T) {
	records := []network.AuditorRegistrationRecord{
		{EffectivePos: types.LogPosition{LogDID: "did:web:log", Sequence: 1}},
		{EffectivePos: types.LogPosition{LogDID: "did:web:log", Sequence: 5}},
	}
	regPath := writeJSONFixture(t, records)
	deps, err := buildJudicialDeps(config.Operational{
		AuditorScope: config.AuditorScopeConfig{RegistryFile: regPath},
	}, freshRegistry(t), nil, nil)
	if err != nil {
		t.Fatalf("buildJudicialDeps: %v", err)
	}
	if len(deps.AuditorRegistry) != 2 {
		t.Errorf("AuditorRegistry len = %d, want 2", len(deps.AuditorRegistry))
	}
}

// Malformed registry file is a boot-fail, not a silent partial snapshot.
func TestBuildJudicialDeps_MalformedRegistry_BootFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := buildJudicialDeps(config.Operational{
		AuditorScope: config.AuditorScopeConfig{RegistryFile: path},
	}, freshRegistry(t), nil, nil)
	if err == nil {
		t.Fatal("expected boot-fail on malformed registry; got nil")
	}
	if !strings.Contains(err.Error(), "load auditor registry") {
		t.Errorf("error should mention 'load auditor registry': %v", err)
	}
}

// ──────────────────────────────────────────────────────────────────
// T6 — buildAuthoritativeResolver
// ──────────────────────────────────────────────────────────────────

// Without a bootstrap file the resolver is (nil, nil) — the legal
// dev/pre-cert posture.
func TestBuildAuthoritativeResolver_NoBootstrap_NilOK(t *testing.T) {
	resolver, err := buildAuthoritativeResolver(config.Operational{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("buildAuthoritativeResolver: %v", err)
	}
	if resolver != nil {
		t.Error("resolver MUST be nil when NetworkBootstrapFile is empty")
	}
}

// With a malformed bootstrap file the resolver constructor surfaces
// the parse error verbatim (no partial-resolver).
func TestBuildAuthoritativeResolver_BadBootstrap_Errors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad-bootstrap.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := buildAuthoritativeResolver(
		config.Operational{NetworkBootstrapFile: path}, nil, nil, nil)
	if err == nil {
		t.Fatal("expected parse error; got nil")
	}
	if !strings.Contains(err.Error(), "load bootstrap") {
		t.Errorf("error should mention 'load bootstrap': %v", err)
	}
}

// buildAuditorScopeAsOf returns a non-nil closure when the bootstrap
// has an ExchangeDID; the closure yields a LogPosition keyed on that
// DID at sequence 0 (the conservative as-of for an audit run that
// pre-dates the JN's on-log walker).
func TestBuildAuditorScopeAsOf_BootstrapPresent_ReturnsClosure(t *testing.T) {
	// J3: the door validates the whole constitution — the fixture must be a
	// complete, valid doc, not a two-field stub.
	bsPath := writeFullBootstrap(t, "did:web:state:tn:network",
		[]string{"did:key:zQ3sample1234567890abcdefghijklmnopqr"})
	cfg := config.Operational{NetworkBootstrapFile: bsPath}
	closure := buildAuditorScopeAsOf(cfg)
	if closure == nil {
		t.Fatal("closure MUST be non-nil when bootstrap has ExchangeDID")
	}
	pos := closure(context.Background())
	if pos.LogDID != "did:web:state:tn:network" {
		t.Errorf("LogDID = %q, want did:web:state:tn:network", pos.LogDID)
	}
	if pos.Sequence != 0 {
		t.Errorf("Sequence = %d, want 0 (genesis)", pos.Sequence)
	}
}

func TestBuildAuditorScopeAsOf_NoBootstrap_ReturnsNil(t *testing.T) {
	if closure := buildAuditorScopeAsOf(config.Operational{}); closure != nil {
		t.Error("closure MUST be nil when NetworkBootstrapFile is empty")
	}
}
