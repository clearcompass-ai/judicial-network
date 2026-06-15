/*
FILE PATH: schemas/judicial_revocation_vector_test.go

DESCRIPTION:

	#124 E2 — the frozen byte-vector for judicial-revocation-v1. E1
	(tests/contracts/delegation_revocation_real_test.go) is the producer lock:
	a real BuildRevocation drives the OriginTip projection and the gate rejects
	the revoked judge. E2 pins the revocation PAYLOAD's canonical bytes so a
	silent schema/marshaling drift (field rename, reorder, tag change) — which
	would change what the ledger advances on Path A and what the resolver reads —
	fails CI visibly. (The full signed entry's bytes aren't deterministic across
	keys; the payload is, and it carries the target_delegation pointer liveness
	depends on.)
*/
package schemas

import (
	"encoding/json"
	"testing"
)

func TestFrozenVector_RevocationPayload(t *testing.T) {
	p := &JudicialRevocationPayload{
		SchemaID:         SchemaJudicialRevocationV1,
		TargetDelegation: LogPositionRef{LogDID: "did:web:state:tn:davidson", Sequence: 42},
		Reason:           "officer_transfer",
		RevokedAt:        "2026-01-01T00:00:00Z",
	}
	got, err := MarshalJudicialRevocationPayload(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"schema_id":"judicial-revocation-v1","target_delegation":{"log_did":"did:web:state:tn:davidson","sequence":42},"reason":"officer_transfer","revoked_at":"2026-01-01T00:00:00Z"}`
	if string(got) != want {
		t.Fatalf("judicial-revocation-v1 canonical bytes drifted (liveness reads target_delegation):\n got:  %s\n want: %s", string(got), want)
	}

	// Codec fixed-point: the frozen bytes decode back to the same payload.
	var rt JudicialRevocationPayload
	if err := json.Unmarshal([]byte(want), &rt); err != nil {
		t.Fatalf("unmarshal frozen vector: %v", err)
	}
	if rt != *p {
		t.Fatalf("round-trip mismatch:\n got:  %+v\n want: %+v", rt, *p)
	}
}
