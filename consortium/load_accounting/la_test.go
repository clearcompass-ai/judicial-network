package load_accounting

import (
	"testing"
	"time"
)

// -------------------------------------------------------------------------
// 1) DefaultLoadAccountingParams
// -------------------------------------------------------------------------

func TestDefaultLoadAccountingParams(t *testing.T) {
	params := DefaultLoadAccountingParams()
	if params.SLAResponseWindow == 0 {
		t.Error("SLAResponseWindow must be set")
	}
	if params.SettlementPeriod == "" {
		t.Error("SettlementPeriod must be set")
	}
}

// -------------------------------------------------------------------------
// 2) BuildLoadAccountingSchema
// -------------------------------------------------------------------------

func TestBuildLoadAccountingSchema(t *testing.T) {
	params := DefaultLoadAccountingParams()
	data, err := BuildLoadAccountingSchema(params)
	if err != nil {
		t.Fatalf("BuildLoadAccountingSchema: %v", err)
	}
	if len(data) == 0 {
		t.Error("schema bytes must not be empty")
	}
}

func TestBuildLoadAccountingSchema_CustomParams(t *testing.T) {
	params := LoadAccountingParams{
		SignerDID:          "did:web:consortium",
		SLAResponseWindow:  10 * time.Minute,
		MaxDrillFrequency:  "monthly",
		ExchangeRate:       0.05,
		SettlementPeriod:   "monthly",
		SurplusExchangeRate: 0.8,
	}
	data, err := BuildLoadAccountingSchema(params)
	if err != nil {
		t.Fatalf("custom params: %v", err)
	}
	if len(data) == 0 {
		t.Error("custom schema must not be empty")
	}
}

// -------------------------------------------------------------------------
// 3) IsObjectiveSLAFailure
// -------------------------------------------------------------------------

func TestIsObjectiveSLAFailure_True(t *testing.T) {
	result := DrillResult{
		NodeDID:      "escrow-node-1",
		Passed:       false,
		ResponseTime: 10 * time.Second,
	}
	if !IsObjectiveSLAFailure(result) {
		t.Error("failed drill should be objective SLA failure")
	}
}

func TestIsObjectiveSLAFailure_False(t *testing.T) {
	result := DrillResult{
		NodeDID:      "escrow-node-1",
		Passed:       true,
		ResponseTime: 100 * time.Millisecond,
	}
	if IsObjectiveSLAFailure(result) {
		t.Error("passed drill should not be SLA failure")
	}
}

// -------------------------------------------------------------------------
// 4) DrillResult struct
// -------------------------------------------------------------------------

func TestDrillResult_Fields(t *testing.T) {
	r := DrillResult{
		NodeDID:      "did:web:escrow-1",
		Passed:       true,
		ResponseTime: 200 * time.Millisecond,
	}
	if r.NodeDID == "" {
		t.Error("NodeDID required")
	}
}

// -------------------------------------------------------------------------
// 5) SettlementLedger struct
// -------------------------------------------------------------------------

func TestSettlementLedger_EnsureMember(t *testing.T) {
	ledger := &SettlementLedger{
		Members: map[string]*MemberUsage{},
	}
	m := ledger.ensureMember("did:web:davidson")
	if m == nil {
		t.Fatal("ensureMember must return non-nil")
	}
	// Second call returns same instance.
	m2 := ledger.ensureMember("did:web:davidson")
	if m != m2 {
		t.Error("should return same instance")
	}
}

func TestSettlementLedger_ToJSON(t *testing.T) {
	ledger := &SettlementLedger{
		Members:  map[string]*MemberUsage{},
		StartPos: 0,
		EndPos:   100,
	}
	ledger.ensureMember("did:web:test")

	data, err := ledger.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("JSON must not be empty")
	}
}

// -------------------------------------------------------------------------
// 6) MemberUsage struct
// -------------------------------------------------------------------------

func TestMemberUsage_Fields(t *testing.T) {
	m := MemberUsage{
		DID:          "did:web:davidson",
		EntryCount:   50000,
		StorageBytes: 25_000_000_000,
	}
	if m.EntryCount != 50000 {
		t.Error("EntryCount mismatch")
	}
}
