/*
FILE PATH: api/exchange/index/scanner_t8_test.go

DESCRIPTION:

	T8 — Scanner's crosslog.DecodeNetworkEntry discrimination contract.

	The scanner needs to distinguish:
	  - JN-domain payloads (case data, schema entries, etc.) → run the
	    per-case indexer (docket_number, artifact_cid, schema_ref).
	  - Network-walker payloads (auditor registrations + scope
	    amendments + witness endpoint declarations + witness identity
	    labels) → SKIP the per-case indexer (these are admin surfaces,
	    not case data).
	  - Malformed payloads → log + skip (boot would have caught structural
	    bugs; runtime entries get a warning).

	libs/crosslog.DecodeNetworkEntry's contract pins this:
	  - JN-domain payload (kind="" or kind="case_v1" etc.) → (nil, nil)
	  - Network kind → (decoded, nil)
	  - Malformed JSON → (nil, ErrMalformedNetworkPayload-wrap)

	The scanner branches on these three outcomes. This file pins the
	contract by exercising DecodeNetworkEntry directly with JN-shaped
	fixtures, without standing up the full ledger query mock.
*/
package index

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/baseproof/tooling/libs/crosslog"
)

// JN-shaped case payload — what scanner.indexDomainPayload normally
// processes. DecodeNetworkEntry MUST return (nil, nil) so the scanner
// falls through to the per-case indexer.
func TestDecodeNetworkEntry_JNCasePayload_NotNetworkKind(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"docket_number": "TN-DAV-2026-CR-001",
		"case_type":     "criminal",
		"filed_date":    "2026-02-01",
	})
	decoded, err := crosslog.DecodeNetworkEntry(payload)
	if err != nil {
		t.Fatalf("unexpected error on JN payload: %v", err)
	}
	if decoded != nil {
		t.Errorf("JN payload MUST NOT decode as network kind; got %+v", decoded)
	}
}

// Domain payload with a "kind" field that's NOT one of the network
// kinds also returns (nil, nil) — the scanner falls through to its
// regular indexer.
func TestDecodeNetworkEntry_UnknownKind_NotNetwork(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"kind":          "BP-ENTRY-CASE-CRIMINAL-V1", // not a network kind
		"docket_number": "TN-DAV-2026-CR-001",
	})
	decoded, err := crosslog.DecodeNetworkEntry(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decoded != nil {
		t.Errorf("non-network kind MUST return nil; got %+v", decoded)
	}
}

// Empty payload returns (nil, nil) — the scanner's nil-decoded branch
// handles this as "not a network entry, fall through."
func TestDecodeNetworkEntry_EmptyPayload_Nil(t *testing.T) {
	decoded, err := crosslog.DecodeNetworkEntry(nil)
	if err != nil {
		t.Errorf("nil payload should not error: %v", err)
	}
	if decoded != nil {
		t.Errorf("nil payload MUST return nil; got %+v", decoded)
	}
}

// Malformed JSON → ErrMalformedNetworkPayload-wrap. The scanner's
// errors.Is(err, ErrMalformedNetworkPayload) branch logs + skips.
func TestDecodeNetworkEntry_MalformedJSON_SentinelErr(t *testing.T) {
	_, err := crosslog.DecodeNetworkEntry([]byte("{not json"))
	if err == nil {
		t.Fatal("malformed JSON MUST error")
	}
	if !errors.Is(err, crosslog.ErrMalformedNetworkPayload) {
		t.Errorf("error MUST wrap ErrMalformedNetworkPayload; got %v", err)
	}
}
