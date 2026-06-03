//go:build e2e

// Phase 1 — On-log Merkle LEAF MODEL contract (S1.3b), SCENARIOS.md.
//
// This is the e2e half of a two-part guard against a leaf-hash mismatch that
// shipped in the SDK and was masked by an in-process stub "echo chamber". The
// other half is a unit test in baseproof (core/envelope/onlog_leaf_test.go) that
// PINS the formula:
//
//	envelope.OnLogEntryLeafHash(canonical) == H(0x00 || SHA256(canonical))
//
// A unit test alone can't catch the bug: a stub tree that hashes leaves the
// same wrong way as the SDK agrees with itself. Only a REAL ledger tree —
// whose leaves Tessera commits as H(0x00 || EntryIdentity), EntryIdentity =
// SHA256(canonical) (clearcompass-ai/ledger tessera/embedded_appender.go:432,
// `Add(tessera.NewEntry(EntryIdentity))`) — is an independent oracle. This test
// takes a real sequenced entry, fetches its real inclusion proof + cosigned
// head from the ledger, and proves the SDK's leaf model reconstructs the
// ledger's committed root (and that the OLD wrong leaf does NOT).
package integration

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	baseprooftypes "github.com/baseproof/baseproof/types"

	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
)

// rawInclusionProof is the JSON shape served by the ledger's
// GET /v1/tree/inclusion/{seq} handler — api/tree.go ->
// tessera/proof_adapter.go RawInclusionProof:
//
//	{"leaf_index": <uint>, "tree_size": <uint>, "hashes": ["<hex>", ...]}
//
// `hashes` is the RFC-6962 sibling co-path, bottom-up: hashes[0] is the
// leaf's immediate sibling; hashes[len-1] is the sibling of the node directly
// below the root. Each is a 32-byte (64 hex char) node hash.
type rawInclusionProof struct {
	LeafIndex uint64   `json:"leaf_index"`
	TreeSize  uint64   `json:"tree_size"`
	Hashes    []string `json:"hashes"`
}

// TestS1_3b_OnLogLeafModel_MatchesLedgerTree is the CONTRACT TEST: the SDK's
// on-log leaf model (envelope.OnLogEntryLeafHash) reconstructs the REAL
// ledger's committed RFC-6962 root from a real inclusion proof, and the OLD
// wrong leaf (envelope.EntryLeafHashBytes over the full canonical) does not.
//
// It is env-gated like the rest of Phase 1: no reachable ledger -> SKIP (not a
// failure), so a bare `go test` is clean offline.
func TestS1_3b_OnLogLeafModel_MatchesLedgerTree(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)

	// 1) Obtain a sequenced on-log entry. The harness carries no canonical-
	//    wire builder (S6.2 is still pending on H1), so — per the scenario's
	//    "OR reuse an already-sequenced entry (seq 0)" path — we reuse the
	//    log's first sequenced leaf. A fresh boot with an empty log skips.
	size, ok := s.HeadSize()
	if !ok || size == 0 {
		t.Skip("no sequenced entries yet — the leaf-model contract needs tree_size>=1")
	}
	const seq uint64 = 0

	// 2) Fetch the entry's canonical wire bytes. These are the exact bytes the
	//    ledger hashed (EntryIdentity = SHA256(canonical)) before handing the
	//    identity to Tessera as leaf DATA.
	rc, canonical, err := s.Ledger.EntryRaw(seq)
	harness.Truthy(t, err == nil, "EntryRaw error: "+harness.ErrStr(err))
	if rc != 200 || len(canonical) == 0 {
		// 302 (redirect to bytestore) or empty body: we can't bind the leaf to
		// real bytes, so the contract is unprovable here — skip rather than
		// fabricate bytes (which would just rebuild the echo chamber).
		t.Skip("entry " + harness.Itoa(int(seq)) + " canonical bytes unavailable (rc=" + harness.Itoa(rc) + ", len=" + harness.Itoa(len(canonical)) + ")")
	}

	// 3a) Fetch the inclusion proof and decode the ledger's JSON shape.
	ic, ibody, err := s.Ledger.Inclusion(seq)
	harness.Truthy(t, err == nil, "Inclusion error: "+harness.ErrStr(err))
	harness.Eq(t, ic, 200, "/v1/tree/inclusion/"+harness.Itoa(int(seq))+" status")
	if ic != 200 {
		return
	}
	var proof rawInclusionProof
	harness.Truthy(t, json.Unmarshal(ibody, &proof) == nil, "inclusion proof not decodable: "+string(ibody))
	harness.Eq(t, proof.LeafIndex, seq, "inclusion leaf_index")
	harness.Truthy(t, proof.TreeSize >= 1, "inclusion tree_size must be >=1")

	// Decode the hex sibling co-path into [32]byte node hashes.
	siblings := make([][32]byte, len(proof.Hashes))
	for i, h := range proof.Hashes {
		b, derr := hex.DecodeString(h)
		harness.Truthy(t, derr == nil, "sibling["+harness.Itoa(i)+"] not hex: "+harness.ErrStr(derr))
		harness.Truthy(t, len(b) == 32, "sibling["+harness.Itoa(i)+"] is "+harness.Itoa(len(b))+" bytes, want 32 (RFC-6962 node hash)")
		if len(b) == 32 {
			copy(siblings[i][:], b)
		}
	}

	// 3b) Fetch the COSIGNED HEAD for the EXACT tree size the proof was built
	//     against. The inclusion handler builds the proof against the latest
	//     head's size; pinning the head to proof.TreeSize via ?size=N makes the
	//     assertion robust against a head advancing between the two calls (and
	//     binds us to the witnessed root, not an unsigned intermediate).
	head, hc, err := s.Ledger.TreeHeadAtSize(proof.TreeSize)
	harness.Truthy(t, err == nil, "TreeHeadAtSize error: "+harness.ErrStr(err))
	if hc != 200 {
		t.Skip("no cosigned head at size " + harness.Itoa(int(proof.TreeSize)) + " (status " + harness.Itoa(hc) + ") — can't bind proof to a witnessed root")
	}
	harness.Eq(t, head.TreeSize, proof.TreeSize, "cosigned head tree_size vs proof tree_size")
	harness.NonEmpty(t, head.RootHash, "cosigned head root_hash")

	rootBytes, derr := hex.DecodeString(head.RootHash)
	harness.Truthy(t, derr == nil, "root_hash not hex: "+harness.ErrStr(derr))
	harness.Truthy(t, len(rootBytes) == 32, "root_hash is "+harness.Itoa(len(rootBytes))+" bytes, want 32")
	if len(rootBytes) != 32 {
		return
	}
	var root [32]byte
	copy(root[:], rootBytes)

	// 4) THE CONTRACT ASSERTION. Reconstruct the RFC-6962 root from the SDK's
	//    authoritative on-log leaf — H(0x00 || SHA256(canonical)) — walked up
	//    the ledger's real sibling co-path, and require it equals the cosigned
	//    (witnessed) RootHash. smt.VerifyMerkleInclusion walks the co-path
	//    bottom-up with the RFC-6962 interior hash H(0x01 || l || r) and, with
	//    core/smt muEnableRootMatch = true, returns an error iff the computed
	//    root != root — so a nil return IS the proof of equality.
	correctLeaf := envelope.OnLogEntryLeafHash(canonical) // H(0x00 || SHA256(canonical))
	correctProof := &baseprooftypes.MerkleProof{
		LeafPosition: proof.LeafIndex,
		LeafHash:     correctLeaf,
		Siblings:     siblings,
		TreeSize:     proof.TreeSize,
	}
	if verr := smt.VerifyMerkleInclusion(correctProof, root); verr != nil {
		t.Fatalf("CONTRACT VIOLATION: SDK on-log leaf H(0x00||SHA256(canonical))=%x does not reconstruct the ledger's cosigned root %x: %v\n"+
			"The SDK's OnLogEntryLeafHash no longer matches what the real ledger tree commits.", correctLeaf, root, verr)
	}

	// 5) THE ECHO-CHAMBER BREAKER (negative). Rebuild the root with the OLD,
	//    WRONG leaf — H(0x00 || canonical), i.e. hashing the FULL canonical as
	//    leaf data instead of its SHA256 identity. This is precisely the leaf
	//    the buggy SDK used; against a real ledger tree it MUST fail to
	//    reconstruct the root. A stub "echo chamber" that hashed its own
	//    leaves the same wrong way would have happily agreed here — which is
	//    exactly why a unit test missed the original bug and this e2e test
	//    catches it. If the two leaves ever coincided (they cannot: one hashes
	//    `canonical`, the other `SHA256(canonical)`), this guard would be
	//    vacuous, so we also assert they differ.
	wrongLeaf := envelope.EntryLeafHashBytes(canonical) // H(0x00 || canonical) — the bug
	harness.Truthy(t, wrongLeaf != correctLeaf, "sanity: wrong leaf must differ from correct leaf (else the negative guard is vacuous)")
	wrongProof := &baseprooftypes.MerkleProof{
		LeafPosition: proof.LeafIndex,
		LeafHash:     wrongLeaf,
		Siblings:     siblings,
		TreeSize:     proof.TreeSize,
	}
	if verr := smt.VerifyMerkleInclusion(wrongProof, root); verr == nil {
		t.Fatalf("ECHO-CHAMBER NOT BROKEN: the WRONG leaf H(0x00||canonical)=%x reconstructed the ledger root %x.\n"+
			"Either the ledger feeds full canonical bytes as leaf data (contract changed) or root-matching is disabled — "+
			"the negative assertion that would have caught the original mismatch is not biting.", wrongLeaf, root)
	}
}
