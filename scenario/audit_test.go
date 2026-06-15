package scenario

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/baseproof/tooling/libs/auth/identity"

	"github.com/clearcompass-ai/judicial-network/delegation"
	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// captureLedger is a delegation.LedgerSubmitter that retains each canonical
// entry by sequence, so a test HTTP server can serve them back for a
// blind-consumer audit (the live submit/poll path is out of scope here — this
// exercises the READ side).
type captureLedger struct {
	mu      sync.Mutex
	logDID  string
	entries [][]byte
}

func (c *captureLedger) SubmitCanonical(_ context.Context, canonical []byte) (schemas.LogPositionRef, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	seq := uint64(len(c.entries))
	c.entries = append(c.entries, append([]byte(nil), canonical...))
	return schemas.LogPositionRef{LogDID: c.logDID, Sequence: seq}, nil
}

// serveMux exposes the captured entries over the ledger's public read surface:
// GET /v1/tree/head and GET /v1/entries/{seq}/raw — the two endpoints
// AuditLedger consumes.
func (c *captureLedger) serveMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tree/head", func(w http.ResponseWriter, _ *http.Request) {
		c.mu.Lock()
		n := len(c.entries)
		c.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree_size":  n,
			"signatures": []any{map[string]any{}}, // one cosignature, shape-only
		})
	})
	mux.HandleFunc("GET /v1/entries/{seq}/raw", func(w http.ResponseWriter, r *http.Request) {
		seq, err := strconv.Atoi(r.PathValue("seq"))
		c.mu.Lock()
		defer c.mu.Unlock()
		if err != nil || seq < 0 || seq >= len(c.entries) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Sequence", strconv.Itoa(seq))
		_, _ = w.Write(c.entries[seq])
	})
	return mux
}

// TestAuditLedger_BlindReadback provisions the full lifecycle through a
// capturing ledger, serves those exact canonical bytes over the public read
// endpoints, and reconstructs the cases as a blind consumer — proving the
// provisioned data is readable + complete with NO access to the registry.
func TestAuditLedger_BlindReadback(t *testing.T) {
	j := DavidsonCounty()
	reg := BuildRegistry(j, testSeed)
	sp := identity.NewStubProvider()
	reg.BindKeys(sp)
	cap := &captureLedger{logDID: j.ExchangeDID}
	bc := &delegation.BuildContext{
		Identity:         sp,
		Submitter:        cap,
		Catalog:          trial.MustRoleCatalog(),
		ExchangeDID:      j.ExchangeDID,
		InstitutionalDID: j.InstitutionalDID,
	}

	const nCases = 4
	if _, err := Provision(context.Background(), bc, reg, nil, ProvisionOptions{
		Cases: nCases, MasterSeed: testSeed, Lifecycle: true,
	}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	srv := httptest.NewServer(cap.serveMux())
	defer srv.Close()

	audit, err := AuditLedger(context.Background(), srv.URL, j.ExchangeDID, srv.Client())
	if err != nil {
		t.Fatalf("AuditLedger: %v", err)
	}

	if int(audit.TreeSize) != len(cap.entries) || audit.Decoded != len(cap.entries) {
		t.Errorf("tree_size=%d decoded=%d, want %d", audit.TreeSize, audit.Decoded, len(cap.entries))
	}
	if len(audit.Cases) != nCases {
		t.Errorf("reconstructed %d cases, want %d", len(audit.Cases), nCases)
	}
	if len(audit.Complete) != nCases {
		t.Errorf("blind read-back found %d complete cases, want %d (incomplete: %v)",
			len(audit.Complete), nCases, audit.Incomplete)
	}
	// Each lifecycle event type appears once per case.
	for _, et := range []string{"case_initiation", "counsel_appearance", "responsive_pleading", "final_judgment"} {
		if audit.EventCounts[et] != nCases {
			t.Errorf("event %q count = %d, want %d", et, audit.EventCounts[et], nCases)
		}
	}
}

// TestExportIdentities writes a KeyFile per principal and checks the population
// is fully materialized with well-formed keys.
func TestExportIdentities(t *testing.T) {
	reg := BuildRegistry(DavidsonCounty(), testSeed)
	dir := t.TempDir()
	n, err := reg.ExportIdentities(dir)
	if err != nil {
		t.Fatalf("ExportIdentities: %v", err)
	}
	want := 1 + len(reg.Officers) + len(reg.Attorneys) // institutional + officers + attorneys
	if n != want {
		t.Errorf("wrote %d identities, want %d", n, want)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != want {
		t.Errorf("found %d key files, want %d", len(files), want)
	}

	// Spot-check one attorney key file: a 32-byte private key + matching DID.
	att := reg.Attorneys[0]
	var found scenario_keyfile
	for _, f := range files {
		var kf scenario_keyfile
		b, _ := os.ReadFile(f)
		if json.Unmarshal(b, &kf) == nil && kf.DID == att.DID {
			found = kf
			break
		}
	}
	if found.DID != att.DID {
		t.Fatalf("no key file for attorney %s", att.DID)
	}
	if len(found.PrivateKeyHex) != 64 {
		t.Errorf("private_key_hex = %d chars, want 64 (32 bytes)", len(found.PrivateKeyHex))
	}
	if found.BPRNumber == "" || found.FilerRole == "" {
		t.Errorf("attorney key file missing bpr_number/filer_role: %+v", found)
	}
}

// scenario_keyfile mirrors the exported KeyFile JSON for the test's spot-check.
type scenario_keyfile struct {
	DID           string `json:"did"`
	PrivateKeyHex string `json:"private_key_hex"`
	FilerRole     string `json:"filer_role"`
	BPRNumber     string `json:"bpr_number"`
}
