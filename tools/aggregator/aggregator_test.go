/*
FILE PATH:
    tools/aggregator/aggregator_test.go

DESCRIPTION:
    Unit tests for the log aggregator. Tests entry deserialization and
    classification by header shape. Does not require Postgres — tests the
    pure classification logic that determines which table each entry targets.

KEY ARCHITECTURAL DECISIONS:
    - Deserializer tested with real SDK builders: constructs entries via
      builder.BuildRootEntity etc., serializes to hex, classifies.
    - Scanner tested for construction only (Run requires operator + DB).
    - Indexer not tested here (requires Postgres). Covered in wave5_tools_test.go
      under sandbox tag.
*/
package aggregator

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// -------------------------------------------------------------------------
// 1) Helpers
// -------------------------------------------------------------------------

func buildAndHex(t *testing.T, entry *envelope.Entry) common.RawEntry {
	t.Helper()
	raw := envelope.Serialize(entry)
	return common.RawEntry{
		Sequence:     42,
		CanonicalHex: hex.EncodeToString(raw),
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return b
}

// -------------------------------------------------------------------------
// 2) Deserializer: classify new case (RootEntity)
// -------------------------------------------------------------------------

func TestClassify_NewCase(t *testing.T) {
	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: "did:web:exchange.test",
		SignerDID: "did:web:test",
		Payload:   mustJSON(t, map[string]any{"docket_number": "2027-CR-001", "case_type": "criminal"}),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	d := NewDeserializer()
	c, err := d.Classify("test-log", buildAndHex(t, entry))
	if err != nil {
		t.Fatalf("classify: %v", err)
	}

	if c.EntryType != "new_case" {
		t.Errorf("type = %q, want new_case", c.EntryType)
	}
	if c.SignerDID != "did:web:test" {
		t.Errorf("signer = %q", c.SignerDID)
	}
	if c.TargetRootSeq != nil {
		t.Error("new case should have nil TargetRootSeq")
	}
}

// -------------------------------------------------------------------------
// 3) Deserializer: classify amendment
// -------------------------------------------------------------------------

func TestClassify_Amendment(t *testing.T) {
	entry, err := builder.BuildAmendment(builder.AmendmentParams{
		Destination: "did:web:exchange.test",
		SignerDID:  "did:web:test",
		TargetRoot: types.LogPosition{LogDID: "test", Sequence: 10},
		Payload:    mustJSON(t, map[string]any{"status": "disposed"}),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	d := NewDeserializer()
	c, err := d.Classify("test-log", buildAndHex(t, entry))
	if err != nil {
		t.Fatalf("classify: %v", err)
	}

	if c.EntryType != "amendment" {
		t.Errorf("type = %q, want amendment", c.EntryType)
	}
	if c.TargetRootSeq == nil || *c.TargetRootSeq != 10 {
		t.Error("amendment must have TargetRootSeq = 10")
	}
	if c.AuthorityPath != "same_signer" {
		t.Errorf("authority = %q, want same_signer", c.AuthorityPath)
	}
}

// -------------------------------------------------------------------------
// 4) Deserializer: classify delegation
// -------------------------------------------------------------------------

func TestClassify_Delegation(t *testing.T) {
	entry, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: "did:web:exchange.test",
		SignerDID:   "did:web:court",
		DelegateDID: "did:web:judge",
		Payload:     mustJSON(t, map[string]any{"role": "judge"}),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	d := NewDeserializer()
	c, err := d.Classify("test-log", buildAndHex(t, entry))
	if err != nil {
		t.Fatalf("classify: %v", err)
	}

	if c.EntryType != "delegation" {
		t.Errorf("type = %q, want delegation", c.EntryType)
	}
	if c.DelegateDID == nil || *c.DelegateDID != "did:web:judge" {
		t.Error("delegation must have DelegateDID")
	}
}

// -------------------------------------------------------------------------
// 5) Deserializer: classify enforcement
// -------------------------------------------------------------------------

func TestClassify_Enforcement(t *testing.T) {
	entry, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: "did:web:exchange.test",
		SignerDID:    "did:web:judge",
		TargetRoot:   types.LogPosition{LogDID: "test", Sequence: 100},
		ScopePointer: types.LogPosition{LogDID: "test", Sequence: 1},
		Payload:      mustJSON(t, map[string]any{"order_type": "sealing_order"}),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	d := NewDeserializer()
	c, err := d.Classify("test-log", buildAndHex(t, entry))
	if err != nil {
		t.Fatalf("classify: %v", err)
	}

	if c.EntryType != "enforcement" {
		t.Errorf("type = %q, want enforcement", c.EntryType)
	}
	if c.AuthorityPath != "scope_authority" {
		t.Errorf("authority = %q, want scope_authority", c.AuthorityPath)
	}
}

// -------------------------------------------------------------------------
// 6) Deserializer: classify Path B order
// -------------------------------------------------------------------------

func TestClassify_PathBOrder(t *testing.T) {
	entry, err := builder.BuildPathBEntry(builder.PathBParams{
		Destination: "did:web:exchange.test",
		SignerDID:          "did:web:judge",
		TargetRoot:         types.LogPosition{LogDID: "test", Sequence: 100},
		DelegationPointers: []types.LogPosition{{LogDID: "test", Sequence: 5}},
		Payload:            mustJSON(t, map[string]any{"action": "order"}),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	d := NewDeserializer()
	c, err := d.Classify("test-log", buildAndHex(t, entry))
	if err != nil {
		t.Fatalf("classify: %v", err)
	}

	if c.EntryType != "path_b_order" {
		t.Errorf("type = %q, want path_b_order", c.EntryType)
	}
	if c.AuthorityPath != "delegation" {
		t.Errorf("authority = %q, want delegation", c.AuthorityPath)
	}
}

// -------------------------------------------------------------------------
// 7) Deserializer: classify commentary
// -------------------------------------------------------------------------

func TestClassify_Commentary(t *testing.T) {
	entry, err := builder.BuildCommentary(builder.CommentaryParams{
		Destination: "did:web:exchange.test",
		SignerDID: "did:web:judge",
		Payload:   mustJSON(t, map[string]any{"type": "recusal"}),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	d := NewDeserializer()
	c, err := d.Classify("test-log", buildAndHex(t, entry))
	if err != nil {
		t.Fatalf("classify: %v", err)
	}

	if c.EntryType != "commentary" {
		t.Errorf("type = %q, want commentary", c.EntryType)
	}
	if c.TargetRootSeq != nil {
		t.Error("commentary must have nil TargetRootSeq")
	}
}

// -------------------------------------------------------------------------
// 8) Deserializer: classify cosignature
// -------------------------------------------------------------------------

func TestClassify_Cosignature(t *testing.T) {
	entry, err := builder.BuildCosignature(builder.CosignatureParams{
		Destination: "did:web:exchange.test",
		SignerDID:     "did:web:clerk",
		CosignatureOf: types.LogPosition{LogDID: "test", Sequence: 50},
		Payload:       mustJSON(t, map[string]any{"endorsement": "approved"}),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	d := NewDeserializer()
	c, err := d.Classify("test-log", buildAndHex(t, entry))
	if err != nil {
		t.Fatalf("classify: %v", err)
	}

	if c.EntryType != "cosignature" {
		t.Errorf("type = %q, want cosignature", c.EntryType)
	}
}

// -------------------------------------------------------------------------
// 9) Deserializer: bad hex → error
// -------------------------------------------------------------------------

func TestClassify_BadHex_Error(t *testing.T) {
	d := NewDeserializer()
	_, err := d.Classify("test", common.RawEntry{CanonicalHex: "not-hex"})
	if err == nil {
		t.Fatal("expected error for bad hex")
	}
}

// -------------------------------------------------------------------------
// 10) Deserializer: corrupted bytes → error
// -------------------------------------------------------------------------

func TestClassify_CorruptedBytes_Error(t *testing.T) {
	d := NewDeserializer()
	_, err := d.Classify("test", common.RawEntry{CanonicalHex: hex.EncodeToString([]byte("garbage"))})
	if err == nil {
		t.Fatal("expected error for corrupted bytes")
	}
}

// -------------------------------------------------------------------------
// 11) Scanner construction
// -------------------------------------------------------------------------

func TestNewScanner_NotNil(t *testing.T) {
	cfg := common.DefaultConfig()
	operator := common.NewOperatorClient("http://localhost:0")
	// DB is nil — scanner can be constructed but not Run.
	s := NewScanner(cfg, operator, nil)
	if s == nil {
		t.Fatal("scanner must not be nil")
	}
}

// -------------------------------------------------------------------------
// 12) Payload extraction
// -------------------------------------------------------------------------

func TestClassify_PayloadExtracted(t *testing.T) {
	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: "did:web:exchange.test",
		SignerDID: "did:web:test",
		Payload:   mustJSON(t, map[string]any{"docket_number": "2027-CR-X", "case_type": "civil"}),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	d := NewDeserializer()
	c, err := d.Classify("test-log", buildAndHex(t, entry))
	if err != nil {
		t.Fatalf("classify: %v", err)
	}

	if c.Payload["docket_number"] != "2027-CR-X" {
		t.Errorf("docket = %v", c.Payload["docket_number"])
	}
	if c.Payload["case_type"] != "civil" {
		t.Errorf("case_type = %v", c.Payload["case_type"])
	}
}
