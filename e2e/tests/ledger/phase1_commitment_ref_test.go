//go:build e2e

// Phase 1 — #190 regression: the SMT-derivation commitment commits as a
// content-addressed REF, not inline mutations (SCENARIOS.md S1.16).
package ledger

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
)

// commitmentInterval mirrors the ledger builder's CommitmentPublisherConfig
// (IntervalEntries): a derivation commitment is published roughly every this
// many committed entries, so the seed must reach it for one to exist.
const commitmentInterval = 1000

// TestS1_16_DerivationCommitmentIsRef_Issue190 pins the bug this whole effort
// started from. At scale the ledger publishes an SMT-derivation commitment; the
// pre-fix code inlined every LeafMutation, so past a few hundred mutations the
// commitment entry's canonical bytes blew the 65,535-byte MaxCanonicalBytes cap
// and admission rejected it with 422. The #190 fix moves the mutations off-log
// behind a content-addressed MutationsCID, so the on-log entry is O(1) for any
// mutation count.
//
// Against the live stack this asserts a published derivation commitment:
//
//	(1) is a REF — mutations_cid is set (the mutations are off-log), and
//	(2) its commentary entry is on the log and far under the cap — i.e. it was
//	    ACCEPTED, not 422'd as it would have been pre-fix.
func TestS1_16_DerivationCommitmentIsRef_Issue190(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireLedger(t)

	size, ok := s.HeadSize()
	if !ok || size < commitmentInterval {
		t.Skip("#190 regression needs a derivation commitment to have been published; " +
			"seed tree_size >= the commitment interval (E2E_SEED_ENTRIES >= " +
			harness.Itoa(commitmentInterval) + "); have tree_size=" + harness.Itoa(int(size)))
	}

	// Probe a spread of sequences for a covering commitment (the exact ranges
	// depend on the builder's batching; any 200 is a published commitment).
	var body []byte
	var found bool
	for _, seq := range []uint64{1, size / 4, size / 2, size * 3 / 4} {
		code, b, err := s.Ledger.DerivationCommitment(seq)
		harness.Truthy(t, err == nil, "DerivationCommitment("+harness.Itoa(int(seq))+") error: "+harness.ErrStr(err))
		if code == 200 {
			body, found = b, true
			break
		}
	}
	if !found {
		t.Skip("no derivation commitment covers the probed sequences yet (tree_size=" + harness.Itoa(int(size)) + ")")
	}

	var c struct {
		RangeStartSeq uint64 `json:"range_start_seq"`
		RangeEndSeq   uint64 `json:"range_end_seq"`
		MutationsCID  string `json:"mutations_cid"`
		MutationCount uint32 `json:"mutation_count"`
		CommentarySeq uint64 `json:"commentary_seq"`
	}
	harness.Truthy(t, json.Unmarshal(body, &c) == nil, "derivation commitment not decodable: "+string(body))

	// (1) #190 core: the commitment is a content-addressed ref — the mutations
	//     live off-log behind MutationsCID, so the on-log entry stays O(1).
	harness.Truthy(t, strings.HasPrefix(c.MutationsCID, "sha256:"),
		"derivation commitment must be a ref (mutations_cid set), got: "+string(body))
	harness.Truthy(t, c.RangeEndSeq >= c.RangeStartSeq,
		"commitment range must be well-formed: "+string(body))

	// (2) the commentary entry that carries the ref is on the log and far under
	//     the 65,535-byte cap — the proof it was accepted, not the pre-fix 422.
	if c.CommentarySeq > 0 {
		rc, raw, err := s.Ledger.EntryRaw(c.CommentarySeq)
		harness.Truthy(t, err == nil, "EntryRaw(commentary "+harness.Itoa(int(c.CommentarySeq))+") error: "+harness.ErrStr(err))
		harness.Eq(t, rc, 200, "commitment commentary entry must be committed on the log (not 422)")
		harness.Truthy(t, len(raw) > 0 && len(raw) < 65535,
			"commitment entry must be under MaxCanonicalBytes — a small ref, not inline mutations; size="+harness.Itoa(len(raw)))
	}
}
