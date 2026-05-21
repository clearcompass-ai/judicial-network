package judicialfindings

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/witness"
)

// wireEncoder is the encode side every finding implements; decode round-trips
// against it. Decode performs NO crypto, so structurally-valid dummy data
// (sigs with SchemeTag != 0) is sufficient to exercise the dispatch.
type wireEncoder interface {
	gossip.Event
	EncodeWireBody() (json.RawMessage, error)
}

func dummySig() types.WitnessSignature {
	return types.WitnessSignature{PubKeyID: [32]byte{0x01}, SchemeTag: 1, SigBytes: []byte{0xAA, 0xBB}}
}

func dummyHead(root byte) types.CosignedTreeHead {
	return types.CosignedTreeHead{
		TreeHead:   types.TreeHead{TreeSize: 100, RootHash: [32]byte{root}, SMTRoot: [32]byte{0xBB}, ReceiptRoot: [32]byte{0xCC}},
		Signatures: []types.WitnessSignature{dummySig()},
	}
}

// allDictionaryFindings builds one structurally-valid instance of every Kind
// in the SDK dictionary.
func allDictionaryFindings(t *testing.T) []wireEncoder {
	t.Helper()
	mk := func(f wireEncoder, err error) wireEncoder {
		t.Helper()
		if err != nil {
			t.Fatalf("construct %T: %v", f, err)
		}
		return f
	}
	rot := types.WitnessRotation{
		CurrentSetHash:    [32]byte{0x01},
		NewSet:            []types.WitnessPublicKey{{ID: [32]byte{0x02}, PublicKey: append([]byte{0x04}, make([]byte, 64)...)}},
		SchemeTagOld:      1,
		CurrentSignatures: []types.WitnessSignature{dummySig()},
		SchemeTagNew:      1,
		NewSignatures:     []types.WitnessSignature{dummySig()},
	}
	return []wireEncoder{
		mk(findings.NewCosignedTreeHeadFinding(dummyHead(0xAA), "ep")),
		mk(findings.NewEquivocationFinding(witness.EquivocationProof{
			TreeSize: 100, HeadA: dummyHead(0xAA), HeadB: dummyHead(0xBB), ValidSigsA: 1, ValidSigsB: 1,
		}, "ep")),
		mk(findings.NewEscrowOverrideFinding(
			cosign.NewEscrowOverridePayload([32]byte{0x11}, [32]byte{0x22}, 123),
			[]types.WitnessSignature{dummySig()})),
		mk(findings.NewOriginatorRotationFinding([]byte{0x02, 0x01, 0x03}, [32]byte{0x09})),
		mk(findings.NewEntryCommitmentEquivocationFinding("did:x", "schema", [32]byte{0x55},
			findings.EntryEquivocatedSide{CanonicalHash: [32]byte{0x01}, EntrySeq: 1, SigBytes: []byte{0xAA}},
			findings.EntryEquivocatedSide{CanonicalHash: [32]byte{0x02}, EntrySeq: 2, SigBytes: []byte{0xBB}})),
		mk(findings.NewGhostLeafFinding(7, 3, [32]byte{0xAB}, "did:log", 1_700_000_000_000_000_000)),
		mk(findings.NewWitnessRotationFinding(rot, "ep")),
		mk(findings.NewCrossLogInclusionFinding("did:src", 5, [32]byte{0x77}, 100, 1_700_000_000_000_000_000)),
	}
}

func TestDecodeWireBody_RoundTripsEveryKind(t *testing.T) {
	got := map[gossip.Kind]bool{}
	for _, f := range allDictionaryFindings(t) {
		raw, err := f.EncodeWireBody()
		if err != nil {
			t.Fatalf("EncodeWireBody %s: %v", f.Kind(), err)
		}
		ev, err := DecodeWireBody(f.Kind(), raw)
		if err != nil {
			t.Fatalf("DecodeWireBody %s: %v", f.Kind(), err)
		}
		if ev.Kind() != f.Kind() {
			t.Errorf("decoded kind = %q, want %q", ev.Kind(), f.Kind())
		}
		got[f.Kind()] = true
	}
	// Every Kind in the SDK dictionary must have been exercised.
	for _, k := range gossip.RegisteredKinds() {
		if !got[k] {
			t.Errorf("Kind %q not covered by decode round-trip", k)
		}
	}
}

func TestDecodeWireBody_UnknownKind(t *testing.T) {
	_, err := DecodeWireBody("AT-GOSSIP-NOPE-V1", json.RawMessage(`{}`))
	if !errors.Is(err, ErrDecode) {
		t.Fatalf("err = %v, want ErrDecode", err)
	}
}

func TestDecodeWireBody_MalformedBody(t *testing.T) {
	_, err := DecodeWireBody(gossip.KindCosignedTreeHead, json.RawMessage(`{not json`))
	if !errors.Is(err, ErrDecode) {
		t.Fatalf("err = %v, want ErrDecode", err)
	}
}

// A registered Kind whose body fails the finding factory's structural checks
// (e.g. zero RootHash) must fail-closed, not yield a half-built finding.
func TestDecodeWireBody_StructurallyInvalidFindingRejected(t *testing.T) {
	bad, err := json.Marshal(gossip.WireCosignedTreeHeadBody{
		Head: gossip.WireCosignedTreeHead{
			RootHash:   "", // invalid
			TreeSize:   100,
			Signatures: []gossip.WireWitnessSignature{{PubKeyID: "01", SchemeTag: 1, SigBytes: "aa"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWireBody(gossip.KindCosignedTreeHead, bad); err == nil {
		t.Fatal("structurally invalid head must fail-closed")
	}
}
