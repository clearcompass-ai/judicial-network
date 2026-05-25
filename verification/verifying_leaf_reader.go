/*
FILE PATH: verification/verifying_leaf_reader.go

DESCRIPTION:

	A proof-anchored smt.LeafReader. Every leaf read is verified against
	the ledger's K-of-N witness-cosigned PUBLISHED HORIZON before it is
	returned — so a judicial ruling that turns on ledger SMT state trusts
	the witness quorum, not the ledger's word.

	# WHY (the headline adoption)

	The plain SDK smt.HTTPLeafReader returns whatever the ledger serves at
	GET /v1/smt/leaf/{key}: a value, with no proof. Injected into the SDK
	verifier walkers (EvaluateAuthority / EvaluateOrigin / WalkDelegationTree)
	that means every authority / origin decision trusts the ledger to report
	its own state honestly. For a judicial network that is the wrong trust
	boundary: the network exists to hold the ledger accountable.

	VerifyingLeafReader replaces the trusted value-lookup with the SDK's
	light-client read (log.VerifyMembershipAsOfHorizon, decomposed here):

	  1. Fetch + cosignature-verify the horizon (the ONE trust step —
	     K-of-N witness signatures over RootHash‖SMTRoot‖ReceiptRoot‖
	     TreeSize). On success head.SMTRoot is a TRUSTED root.
	  2. Fetch the membership / non-membership proof for the key, generated
	     as-of that same horizon's smt_root.
	  3. Verify the proof against head.SMTRoot. By soundness of SHA-256 the
	     leaf state (or its absence) is now witness-anchored.

	# ABSENCE — smt.LeafReader CONTRACT

	smt.LeafReader.Get returns (nil, nil) for a key not in the tree (the
	plain HTTPLeafReader maps a 404 to that). VerifyingLeafReader preserves
	the contract: a VERIFIED non-membership proof → (nil, nil). The
	difference from the plain reader is that absence is now PROVEN against
	the witnessed root, not asserted by the ledger. This is why Get composes
	the membership / non-membership primitives directly rather than calling
	log.VerifyMembershipAsOfHorizon (which treats a served non-membership
	proof as an error, since it has no way to signal "verified absence" to
	the LeafReader contract).

	# HORIZON CACHE (one fetch, many keys)

	A single verification (e.g. a delegation-tree walk) reads many leaves.
	Re-fetching + re-verifying the horizon per key would be N round-trips +
	N quorum checks. The verified horizon is cached for HorizonTTL, so a
	burst of reads does ONE horizon fetch + cosig-verify and N proof
	fetches. A concurrent refetch is coalesced under the mutex (the first
	caller fetches; the rest reuse the fresh cache) — a poor man's
	singleflight, no thundering herd. The horizon advances slowly (only on
	a durable, freshly-cosigned checkpoint), so a short TTL keeps reads
	fresh without hammering the ledger.

	# FAILS CLOSED

	Any failure — horizon not published (pre-genesis), horizon below quorum,
	proof transport error, or a proof that does not resolve against the
	witnessed root — surfaces as an error. The verifier then refuses to rule
	on unverified state rather than falling back to a trusted value.

KEY DEPENDENCIES:
  - attesta/log.HTTPCheckpointClient   (FetchVerifiedHorizon — trust step)
  - attesta/core/smt.HTTPProofReader   (proof transport)
  - attesta/core/smt.VerifyMembershipProof / VerifyNonMembershipProof
  - attesta/crypto/cosign.WitnessKeySet (the K-of-N trust root)
*/
package verification

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/clearcompass-ai/attesta/core/smt"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/types"
)

// defaultHorizonTTL matches the SDK witness.TreeHeadClient default
// (30s) — the same freshness window the JN already applies to live
// tree-head reads.
const defaultHorizonTTL = 30 * time.Second

// VerifyingLeafReader is an smt.LeafReader that verifies every read
// against the witness-cosigned horizon. Safe for concurrent use.
type VerifyingLeafReader struct {
	cp  *sdklog.HTTPCheckpointClient
	pr  *smt.HTTPProofReader
	set *cosign.WitnessKeySet
	ttl time.Duration

	mu        sync.Mutex
	cached    types.CosignedTreeHead
	cachedAt  time.Time
	haveCache bool
}

// VerifyingLeafReaderConfig wires the three SDK clients + the trust set.
// All three clients should point at the SAME ledger base URL — the leaf,
// its proof, and the horizon the proof is checked against must all come
// from the one log being read.
type VerifyingLeafReaderConfig struct {
	// Checkpoint fetches + cosignature-verifies the horizon. Required.
	Checkpoint *sdklog.HTTPCheckpointClient

	// Proofs fetches per-key membership / non-membership proofs. Required.
	Proofs *smt.HTTPProofReader

	// WitnessSet is the K-of-N trust root for the log being read — the
	// witnesses whose quorum cosigns this log's horizon. Required.
	WitnessSet *cosign.WitnessKeySet

	// HorizonTTL caps how long a verified horizon is reused across reads.
	// Zero applies defaultHorizonTTL.
	HorizonTTL time.Duration
}

// NewVerifyingLeafReader validates the wiring and returns the reader.
func NewVerifyingLeafReader(cfg VerifyingLeafReaderConfig) (*VerifyingLeafReader, error) {
	if cfg.Checkpoint == nil {
		return nil, fmt.Errorf("verification/verifying_leaf_reader: nil checkpoint client")
	}
	if cfg.Proofs == nil {
		return nil, fmt.Errorf("verification/verifying_leaf_reader: nil proof reader")
	}
	if cfg.WitnessSet == nil {
		return nil, fmt.Errorf("verification/verifying_leaf_reader: nil witness key set")
	}
	ttl := cfg.HorizonTTL
	if ttl <= 0 {
		ttl = defaultHorizonTTL
	}
	return &VerifyingLeafReader{
		cp:  cfg.Checkpoint,
		pr:  cfg.Proofs,
		set: cfg.WitnessSet,
		ttl: ttl,
	}, nil
}

// Get reads a leaf by key and returns it ONLY if a membership proof for
// the key verifies against the witnessed horizon's smt_root. A verified
// non-membership proof returns (nil, nil) — the smt.LeafReader "not
// found" contract, here proven rather than asserted. Any other outcome is
// an error (fails closed).
func (r *VerifyingLeafReader) Get(ctx context.Context, key [32]byte) (*types.SMTLeaf, error) {
	head, err := r.horizon(ctx)
	if err != nil {
		return nil, fmt.Errorf("verifyingleaf: horizon: %w", err)
	}
	res, err := r.pr.Proof(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("verifyingleaf: proof for %x: %w", key[:8], err)
	}
	if res.Membership {
		if err := smt.VerifyMembershipProof(res.Proof, head.SMTRoot); err != nil {
			return nil, fmt.Errorf("verifyingleaf: membership proof for %x does not verify against witnessed smt_root: %w", key[:8], err)
		}
		// VerifyMembershipProof guarantees TerminalLeaf != nil.
		return res.Proof.TerminalLeaf, nil
	}
	if err := smt.VerifyNonMembershipProof(res.Proof, head.SMTRoot); err != nil {
		return nil, fmt.Errorf("verifyingleaf: non-membership proof for %x does not verify against witnessed smt_root: %w", key[:8], err)
	}
	return nil, nil
}

// horizon returns the cached verified horizon when fresh, else fetches +
// cosignature-verifies a new one. The fetch happens under the lock so a
// concurrent burst coalesces into a single round-trip.
func (r *VerifyingLeafReader) horizon(ctx context.Context) (types.CosignedTreeHead, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.haveCache && time.Since(r.cachedAt) < r.ttl {
		return r.cached, nil
	}
	head, err := r.cp.FetchVerifiedHorizon(ctx, r.set)
	if err != nil {
		return types.CosignedTreeHead{}, err
	}
	r.cached = head
	r.cachedAt = time.Now()
	r.haveCache = true
	return head, nil
}
