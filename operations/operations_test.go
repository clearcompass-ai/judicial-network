package operations

import (
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------
// 1) Empty SignerDID → error
// -------------------------------------------------------------------------

func TestPublishEvent_EmptySignerDID(t *testing.T) {
	_, err := PublishEvent(EventConfig{EventType: "scheduling"})
	if err == nil {
		t.Fatal("expected error for empty SignerDID")
	}
}

// -------------------------------------------------------------------------
// 2) Empty EventType → error
// -------------------------------------------------------------------------

func TestPublishEvent_EmptyEventType(t *testing.T) {
	_, err := PublishEvent(EventConfig{SignerDID: "did:web:test"})
	if err == nil {
		t.Fatal("expected error for empty EventType")
	}
}

// -------------------------------------------------------------------------
// 3) Scheduling event: entry built, payload correct
// -------------------------------------------------------------------------

func TestPublishEvent_Scheduling(t *testing.T) {
	result, err := PublishEvent(EventConfig{
		SignerDID: "did:web:courts.nashville.gov:role:scheduling-system-2026",
		EventType: "scheduling",
		EventTime: 1700000000,
		Payload: map[string]interface{}{
			"hearing_type":   "motion",
			"scheduled_date": "2027-05-01",
			"courtroom":      "4A",
		},
	})
	if err != nil {
		t.Fatalf("PublishEvent: %v", err)
	}
	if result.Entry == nil {
		t.Fatal("Entry is nil")
	}
	if result.EventType != "scheduling" {
		t.Errorf("EventType = %q", result.EventType)
	}
	if result.RefCount != 0 {
		t.Errorf("RefCount = %d, want 0", result.RefCount)
	}

	// Verify payload contains event_type.
	var parsed map[string]any
	json.Unmarshal(result.Entry.DomainPayload, &parsed)
	if parsed["event_type"] != "scheduling" {
		t.Errorf("payload event_type = %v", parsed["event_type"])
	}
	if parsed["courtroom"] != "4A" {
		t.Errorf("payload courtroom = %v", parsed["courtroom"])
	}
}

// -------------------------------------------------------------------------
// 4) Closure event: no Refs, refs omitted from payload
// -------------------------------------------------------------------------

func TestPublishEvent_Closure_NoRefs(t *testing.T) {
	result, err := PublishEvent(EventConfig{
		SignerDID: "did:web:courts.nashville.gov",
		EventType: "closure",
		Payload: map[string]interface{}{
			"reason":         "weather",
			"effective_date": "2027-04-20",
		},
	})
	if err != nil {
		t.Fatalf("closure: %v", err)
	}
	if result.RefCount != 0 {
		t.Errorf("RefCount = %d", result.RefCount)
	}

	var parsed map[string]any
	json.Unmarshal(result.Entry.DomainPayload, &parsed)
	if _, hasRefs := parsed["refs"]; hasRefs {
		t.Error("closure should not have refs in payload")
	}
}

// -------------------------------------------------------------------------
// 5) Multi-ref consolidated event
// -------------------------------------------------------------------------

func TestPublishEvent_MultiRef(t *testing.T) {
	refs := []types.LogPosition{
		{LogDID: "did:web:court:cases", Sequence: 100},
		{LogDID: "did:web:court:cases", Sequence: 200},
		{LogDID: "did:web:court:cases", Sequence: 300},
	}
	result, err := PublishEvent(EventConfig{
		SignerDID: "did:web:court",
		EventType: "consolidated_hearing",
		Refs:      refs,
	})
	if err != nil {
		t.Fatalf("multi-ref: %v", err)
	}
	if result.RefCount != 3 {
		t.Errorf("RefCount = %d, want 3", result.RefCount)
	}

	var parsed map[string]any
	json.Unmarshal(result.Entry.DomainPayload, &parsed)
	refsSlice, ok := parsed["refs"].([]interface{})
	if !ok || len(refsSlice) != 3 {
		t.Errorf("payload refs = %v", parsed["refs"])
	}
}

// -------------------------------------------------------------------------
// 6) Serialize roundtrip
// -------------------------------------------------------------------------

func TestPublishEvent_SerializeRoundtrip(t *testing.T) {
	result, err := PublishEvent(EventConfig{
		SignerDID: "did:web:test",
		EventType: "notice",
		Payload:   map[string]interface{}{"text": "procedure change"},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	raw := envelope.Serialize(result.Entry)
	restored, err := envelope.Deserialize(raw)
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	if len(restored.DomainPayload) == 0 {
		t.Error("restored payload must not be empty")
	}
}

// -------------------------------------------------------------------------
// 7) EventResult fields populated
// -------------------------------------------------------------------------

func TestPublishEvent_ResultFields(t *testing.T) {
	result, _ := PublishEvent(EventConfig{
		SignerDID: "did:web:test",
		EventType: "duty",
		Refs:      []types.LogPosition{{LogDID: "did:web:x", Sequence: 1}},
	})
	if result.Entry == nil {
		t.Fatal("Entry nil")
	}
	if result.EventType != "duty" {
		t.Errorf("EventType = %q", result.EventType)
	}
	if result.RefCount != 1 {
		t.Errorf("RefCount = %d", result.RefCount)
	}
}
