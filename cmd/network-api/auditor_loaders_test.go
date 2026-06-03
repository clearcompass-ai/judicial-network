/*
FILE PATH: cmd/network-api/auditor_loaders_test.go

DESCRIPTION:

	Unit tests for loadAuditorRegistry + loadAuditorAmendments.

	Pinned properties:
	  1. Empty path returns (nil, nil) — disables the scope gate.
	  2. Missing file returns a wrapped read error.
	  3. Malformed JSON returns a wrapped parse error.
	  4. Unsorted records (EffectivePos non-monotonic) boot-fail.
	  5. Sorted records round-trip cleanly.
*/
package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// ──────────────────────────────────────────────────────────────────
// loadAuditorRegistry
// ──────────────────────────────────────────────────────────────────

func TestLoadAuditorRegistry_EmptyPath_ReturnsNil(t *testing.T) {
	got, err := loadAuditorRegistry("")
	if err != nil {
		t.Fatalf("loadAuditorRegistry(\"\"): unexpected err %v", err)
	}
	if got != nil {
		t.Errorf("loadAuditorRegistry(\"\"): want nil, got %v", got)
	}
}

func TestLoadAuditorRegistry_MissingFile_Errors(t *testing.T) {
	_, err := loadAuditorRegistry("/no/such/file/auditor_registry.json")
	if err == nil {
		t.Fatal("expected error reading missing file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error should wrap os.ErrNotExist: %v", err)
	}
}

func TestLoadAuditorRegistry_MalformedJSON_Errors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadAuditorRegistry(path)
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
	if !strings.Contains(err.Error(), "parse auditor registry") {
		t.Errorf("error should mention 'parse auditor registry': %v", err)
	}
}

func TestLoadAuditorRegistry_Unsorted_Errors(t *testing.T) {
	records := []network.AuditorRegistrationRecord{
		{EffectivePos: types.LogPosition{LogDID: "did:web:log", Sequence: 5}},
		{EffectivePos: types.LogPosition{LogDID: "did:web:log", Sequence: 2}}, // out of order
	}
	path := writeJSONFixture(t, records)
	_, err := loadAuditorRegistry(path)
	if err == nil {
		t.Fatal("expected unsorted-records error")
	}
	if !strings.Contains(err.Error(), "unsorted") {
		t.Errorf("error should mention 'unsorted': %v", err)
	}
}

func TestLoadAuditorRegistry_Sorted_RoundTrips(t *testing.T) {
	records := []network.AuditorRegistrationRecord{
		{EffectivePos: types.LogPosition{LogDID: "did:web:log", Sequence: 1}},
		{EffectivePos: types.LogPosition{LogDID: "did:web:log", Sequence: 5}},
		{EffectivePos: types.LogPosition{LogDID: "did:web:log", Sequence: 10}},
	}
	path := writeJSONFixture(t, records)
	got, err := loadAuditorRegistry(path)
	if err != nil {
		t.Fatalf("loadAuditorRegistry: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d records, want 3", len(got))
	}
	if got[0].EffectivePos.Sequence != 1 || got[2].EffectivePos.Sequence != 10 {
		t.Errorf("records out of order: %+v", got)
	}
}

func TestLoadAuditorRegistry_EmptyArray_Loads(t *testing.T) {
	path := writeJSONFixture(t, []network.AuditorRegistrationRecord{})
	got, err := loadAuditorRegistry(path)
	if err != nil {
		t.Fatalf("loadAuditorRegistry: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %d records", len(got))
	}
}

// ──────────────────────────────────────────────────────────────────
// loadAuditorAmendments — mirror of registry tests
// ──────────────────────────────────────────────────────────────────

func TestLoadAuditorAmendments_EmptyPath_ReturnsNil(t *testing.T) {
	got, err := loadAuditorAmendments("")
	if err != nil {
		t.Fatalf("loadAuditorAmendments(\"\"): unexpected err %v", err)
	}
	if got != nil {
		t.Errorf("loadAuditorAmendments(\"\"): want nil, got %v", got)
	}
}

func TestLoadAuditorAmendments_Unsorted_Errors(t *testing.T) {
	records := []network.AuditorScopeAmendmentRecord{
		{EffectivePos: types.LogPosition{LogDID: "did:web:log", Sequence: 5}},
		{EffectivePos: types.LogPosition{LogDID: "did:web:log", Sequence: 2}},
	}
	path := writeJSONFixture(t, records)
	_, err := loadAuditorAmendments(path)
	if err == nil {
		t.Fatal("expected unsorted-records error")
	}
}

func TestLoadAuditorAmendments_Sorted_RoundTrips(t *testing.T) {
	records := []network.AuditorScopeAmendmentRecord{
		{EffectivePos: types.LogPosition{LogDID: "did:web:log", Sequence: 3}},
		{EffectivePos: types.LogPosition{LogDID: "did:web:log", Sequence: 7}},
	}
	path := writeJSONFixture(t, records)
	got, err := loadAuditorAmendments(path)
	if err != nil {
		t.Fatalf("loadAuditorAmendments: %v", err)
	}
	if len(got) != 2 || got[0].EffectivePos.Sequence != 3 || got[1].EffectivePos.Sequence != 7 {
		t.Errorf("records out of order or wrong count: %+v", got)
	}
}

// writeJSONFixture writes v as JSON to a temp file and returns the path.
func writeJSONFixture(t *testing.T, v any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.json")
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}
