//go:build e2e

// Phase 1 — On-log inclusion across an IMPERFECT tree (S1.3c), SCENARIOS.md.
//
// Companion to S1.3b, which proves the leaf model at ONE position (seq 0). That
// is not enough to pin the v1.41.0 core/smt fix (attesta 92eeb2c), a
// POSITION-DEPENDENT bug: VerifyMerkleInclusion paired the RFC-6962 co-path by
// leaf-index parity — correct ONLY for perfect (power-of-two) trees — and
// REJECTED valid canonical proofs for ~27% of leaves on an imperfect tree. A
// single-position test on the historical 2^2=4-entry seed (a PERFECT tree) never
// exercises the imperfect co-path at all ("old tests are 2^2").
//
// S1.3c requires an IMPERFECT tree and verifies inclusion at the BOUNDARY
// positions where index-parity pairing diverges from canonical RFC-6962 (the
// first/last/orphan leaves, the 2^k split and its neighbours), each via the SDK's
// OnLogEntryLeafHash + VerifyMerkleInclusion against the witness-cosigned root.
package integration

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/core/smt"
	attestatypes "github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
)

func isPow2(n uint64) bool { return n != 0 && n&(n-1) == 0 }

// inclusionBoundaryPositions returns the leaf indices in [0,size) most likely to
// expose an RFC-6962 co-path pairing bug on an IMPERFECT tree.
func inclusionBoundaryPositions(size uint64) []uint64 {
	if size == 0 {
		return nil
	}
	p := uint64(1) // largest power of two strictly less than size (the top split).
	for p<<1 < size {
		p <<= 1
	}
	cand := []uint64{0, 1, 2, p - 1, p, p + 1, size / 3, size / 2, size - 2, size - 1}
	seen := map[uint64]bool{}
	out := make([]uint64, 0, len(cand))
	for _, c := range cand {
		if c < size && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// TestS1_3c_InclusionBoundarySweep_ImperfectTree sweeps the boundary leaf
// positions of a REAL imperfect ledger tree and proves the SDK reconstructs the
// cosigned root at each — the position-aware regression guard for v1.41.0.
func TestS1_3c_InclusionBoundarySweep_ImperfectTree(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)

	size, ok := s.HeadSize()
	if !ok || size < 7 {
		t.Skip("imperfect-tree inclusion sweep needs tree_size>=7 (set E2E_SEED_ENTRIES to an imperfect size); have " + harness.Itoa(int(size)))
	}
	if isPow2(size) {
		t.Skip("tree_size=" + harness.Itoa(int(size)) + " is a power of two — seed an imperfect count (e.g. E2E_SEED_ENTRIES=11) to exercise the v1.41.0 fix")
	}

	attempted, verified := 0, 0
	for _, seq := range inclusionBoundaryPositions(size) {
		rc, canonical, err := s.Ledger.EntryRaw(seq)
		harness.Truthy(t, err == nil, "EntryRaw("+harness.Itoa(int(seq))+") error: "+harness.ErrStr(err))
		if rc != 200 || len(canonical) == 0 {
			continue // bytestore redirect / empty — can't bind this leaf to real bytes
		}
		ic, ibody, err := s.Ledger.Inclusion(seq)
		harness.Truthy(t, err == nil, "Inclusion("+harness.Itoa(int(seq))+") error: "+harness.ErrStr(err))
		harness.Eq(t, ic, 200, "/v1/tree/inclusion/"+harness.Itoa(int(seq))+" status")
		if ic != 200 {
			continue
		}
		var proof rawInclusionProof
		harness.Truthy(t, json.Unmarshal(ibody, &proof) == nil, "inclusion proof not decodable at seq "+harness.Itoa(int(seq))+": "+string(ibody))
		harness.Eq(t, proof.LeafIndex, seq, "inclusion leaf_index at seq "+harness.Itoa(int(seq)))

		siblings := make([][32]byte, len(proof.Hashes))
		for i, h := range proof.Hashes {
			b, derr := hex.DecodeString(h)
			harness.Truthy(t, derr == nil && len(b) == 32, "sibling["+harness.Itoa(i)+"] not a 32-byte node hash at seq "+harness.Itoa(int(seq)))
			if len(b) == 32 {
				copy(siblings[i][:], b)
			}
		}

		head, hc, err := s.Ledger.TreeHeadAtSize(proof.TreeSize)
		harness.Truthy(t, err == nil, "TreeHeadAtSize error at seq "+harness.Itoa(int(seq))+": "+harness.ErrStr(err))
		if hc != 200 {
			continue
		}
		rootBytes, derr := hex.DecodeString(head.RootHash)
		harness.Truthy(t, derr == nil && len(rootBytes) == 32, "root_hash not a 32-byte hash at seq "+harness.Itoa(int(seq)))
		if len(rootBytes) != 32 {
			continue
		}
		var root [32]byte
		copy(root[:], rootBytes)

		attempted++
		correctProof := &attestatypes.MerkleProof{
			LeafPosition: proof.LeafIndex,
			LeafHash:     envelope.OnLogEntryLeafHash(canonical), // H(0x00 || SHA256(canonical))
			Siblings:     siblings,
			TreeSize:     proof.TreeSize,
		}
		if verr := smt.VerifyMerkleInclusion(correctProof, root); verr != nil {
			t.Fatalf("IMPERFECT-TREE INCLUSION REGRESSION at leaf %d of %d: the SDK on-log leaf does not "+
				"reconstruct the witness-cosigned root %x: %v\n"+
				"This is the v1.41.0 RFC-6962 imperfect-tree pairing bug — the fix in core/smt/verify.go is not biting here.",
				seq, proof.TreeSize, root, verr)
		}
		verified++
	}

	if attempted == 0 {
		t.Skip("no boundary position offered inline canonical bytes + a cosigned head (bytestore-redirect config); S1.3b covers the single-position contract")
	}
	t.Logf("imperfect-tree inclusion sweep PASS: %d/%d boundary positions reconstruct the witness-cosigned root on a size-%d (imperfect) tree", verified, attempted, size)
}
