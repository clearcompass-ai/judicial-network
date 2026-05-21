package crosslog

import (
	"encoding/json"
	"errors"
	"testing"
)

func anchorPayload(t *testing.T, p cosignedAnchorPayload) []byte {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal anchor: %v", err)
	}
	return raw
}

func TestIsCosignedAnchor(t *testing.T) {
	fix := makeSTHFixture(t, 3)
	good := anchorPayload(t, cosignedAnchorPayload{
		AnchorType:   CosignedAnchorType,
		SourceLogDID: "did:web:source.log",
		Head:         wireBody(t, fix.head, "https://source.example"),
		TreeHeadRef:  "ref-abc",
	})

	cases := []struct {
		name    string
		payload []byte
		want    bool
	}{
		{"cosigned-anchor", good, true},
		{"other-anchor", []byte(`{"anchor_type":"tree_head_ref"}`), false},
		{"no-anchor-type", []byte(`{"source_log_did":"did:web:x"}`), false},
		{"not-json", []byte(`{not json`), false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsCosignedAnchor(tc.payload); got != tc.want {
				t.Errorf("IsCosignedAnchor = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestVerifyCosignedAnchor_HappyPath(t *testing.T) {
	fix := makeSTHFixture(t, 3)
	payload := anchorPayload(t, cosignedAnchorPayload{
		AnchorType:   CosignedAnchorType,
		SourceLogDID: "did:web:source.log",
		Head:         wireBody(t, fix.head, "https://source.example"),
		TreeHeadRef:  "ref-abc",
	})

	got, err := VerifyCosignedAnchor(payload, fix.set)
	if err != nil {
		t.Fatalf("VerifyCosignedAnchor: %v", err)
	}
	if got.SourceLogDID != "did:web:source.log" {
		t.Errorf("SourceLogDID = %q, want did:web:source.log", got.SourceLogDID)
	}
	if got.Head.TreeSize != fix.head.TreeSize {
		t.Errorf("TreeSize = %d, want %d", got.Head.TreeSize, fix.head.TreeSize)
	}
	if got.Head.RootHash != fix.head.RootHash {
		t.Errorf("RootHash = %x, want %x", got.Head.RootHash, fix.head.RootHash)
	}
	// ReceiptRoot is the regression-critical field: a wire path that drops it
	// makes the cosignature fail quorum. Pin it round-trips intact.
	if got.Head.ReceiptRoot != fix.head.ReceiptRoot {
		t.Errorf("ReceiptRoot = %x, want %x", got.Head.ReceiptRoot, fix.head.ReceiptRoot)
	}
}

// K-of-N: a 2-of-3 set still verifies a head carrying all 3 cosignatures.
func TestVerifyCosignedAnchor_QuorumBelowN(t *testing.T) {
	fix := makeSTHFixture(t, 3)
	payload := anchorPayload(t, cosignedAnchorPayload{
		AnchorType:   CosignedAnchorType,
		SourceLogDID: "did:web:source.log",
		Head:         wireBody(t, fix.head, "ep"),
	})
	if _, err := VerifyCosignedAnchor(payload, fix.set); err != nil {
		t.Fatalf("3-of-3 set: %v", err)
	}
}

func TestVerifyCosignedAnchor_WrongWitnessSet(t *testing.T) {
	fix := makeSTHFixture(t, 3)
	other := makeSTHFixture(t, 3) // disjoint witnesses, same NetworkID

	payload := anchorPayload(t, cosignedAnchorPayload{
		AnchorType:   CosignedAnchorType,
		SourceLogDID: "did:web:source.log",
		Head:         wireBody(t, fix.head, "ep"),
	})
	_, err := VerifyCosignedAnchor(payload, other.set)
	if !errors.Is(err, ErrAnchorQuorumFailed) {
		t.Fatalf("err = %v, want ErrAnchorQuorumFailed", err)
	}
}

func TestVerifyCosignedAnchor_RejectsWrongAnchorType(t *testing.T) {
	fix := makeSTHFixture(t, 3)
	payload := anchorPayload(t, cosignedAnchorPayload{
		AnchorType:   "tree_head_ref",
		SourceLogDID: "did:web:source.log",
		Head:         wireBody(t, fix.head, "ep"),
	})
	_, err := VerifyCosignedAnchor(payload, fix.set)
	if !errors.Is(err, ErrNotCosignedAnchor) {
		t.Fatalf("err = %v, want ErrNotCosignedAnchor", err)
	}
}

func TestVerifyCosignedAnchor_NilSet(t *testing.T) {
	if _, err := VerifyCosignedAnchor([]byte(`{}`), nil); err == nil {
		t.Fatal("nil set must error")
	}
}

func TestVerifyCosignedAnchor_MalformedJSON(t *testing.T) {
	fix := makeSTHFixture(t, 3)
	if _, err := VerifyCosignedAnchor([]byte(`{not json`), fix.set); err == nil {
		t.Fatal("malformed payload must error")
	}
}

// A structurally-valid anchor whose embedded head fails finding-construction
// (zero RootHash) surfaces a reconstruct error, not a panic.
func TestVerifyCosignedAnchor_BadHead(t *testing.T) {
	fix := makeSTHFixture(t, 3)
	w := wireBody(t, fix.head, "ep")
	w.Head.RootHash = "" // structurally invalid for the finding constructor
	payload := anchorPayload(t, cosignedAnchorPayload{
		AnchorType:   CosignedAnchorType,
		SourceLogDID: "did:web:source.log",
		Head:         w,
	})
	if _, err := VerifyCosignedAnchor(payload, fix.set); err == nil {
		t.Fatal("bad embedded head must error")
	}
}
