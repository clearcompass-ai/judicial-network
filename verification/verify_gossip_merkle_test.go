package verification

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
	tessera "github.com/transparency-dev/tessera/client"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
)

const merkleSrc = "did:web:peer.source.log"

// buildMerkleTree appends n distinct leaves to an RFC 6962 test tree.
func buildMerkleTree(n int) *testonly.Tree {
	tree := testonly.New(rfc6962.DefaultHasher)
	for i := 0; i < n; i++ {
		tree.AppendData([]byte{byte(i)})
	}
	return tree
}

// treeTileFetcher serves canonical level-0 tile bytes from a test tree —
// the in-memory stand-in for a peer's Static-CT tile mirror.
func treeTileFetcher(tree *testonly.Tree) tessera.TileFetcherFunc {
	return func(_ context.Context, level, index uint64, p uint8) ([]byte, error) {
		if level != 0 || index != 0 {
			return nil, fmt.Errorf("tile fetcher: only (0,0) supported, got (%d,%d)", level, index)
		}
		want := uint64(p)
		if p == 0 {
			want = tree.Size()
		}
		var buf bytes.Buffer
		for i := uint64(0); i < want; i++ {
			buf.Write(tree.LeafHash(i))
		}
		return buf.Bytes(), nil
	}
}

type fixedTiles struct {
	did string
	f   tessera.TileFetcherFunc
}

func (x fixedTiles) FetcherFor(did string) (tessera.TileFetcherFunc, bool) {
	if did == x.did {
		return x.f, true
	}
	return nil, false
}

type fixedHead struct {
	did  string
	head types.TreeHead
}

func (x fixedHead) TrustedHead(did string) (types.TreeHead, bool) {
	if did == x.did {
		return x.head, true
	}
	return types.TreeHead{}, false
}

func merkleVerifier(t *testing.T, head types.TreeHead, tiles TileFetcherSource) *GossipVerifier {
	t.Helper()
	gv, err := NewGossipVerifier(GossipVerifierConfig{
		Envelope:    stubEnvelope{},
		WitnessSets: NewWitnessSetRegistry(map[string]*cosign.WitnessKeySet{}, vgNetworkID()),
		Heads:       fixedHead{did: merkleSrc, head: head},
		Tiles:       tiles,
	})
	if err != nil {
		t.Fatal(err)
	}
	return gv
}

// End-to-end: a genuine inclusion proof verifies through the full pull-path
// seam (envelope → decode → router → CrossLogInclusion.Verify tile replay).
// The gossip originator (relayer) is deliberately NOT the source log, proving
// head + tiles are keyed by the finding's own SourceLogDID.
func TestGossipVerifier_CrossLogInclusion_E2E_TrueInclusion(t *testing.T) {
	tree := buildMerkleTree(8)
	var leafHash, root [32]byte
	copy(leafHash[:], tree.LeafHash(3))
	copy(root[:], tree.HashAt(8))

	gv := merkleVerifier(t, types.TreeHead{TreeSize: 8, RootHash: root},
		fixedTiles{did: merkleSrc, f: treeTileFetcher(tree)})

	f, err := findings.NewCrossLogInclusionFinding(merkleSrc, 3, leafHash, 8, 1_700_000_000_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gv.Verify(context.Background(), signedEventForFinding(t, "did:web:reporter.relay", f))
	if err != nil {
		t.Fatalf("Verify genuine inclusion: %v", err)
	}
	if got.Kind() != gossip.KindCrossLogInclusion {
		t.Fatalf("kind = %q", got.Kind())
	}
}

// A forged source root must reject — the proof is RFC 6962-checked against the
// trusted head's RootHash, so the mirror cannot launder a bad root.
func TestGossipVerifier_CrossLogInclusion_E2E_ForgedRoot(t *testing.T) {
	tree := buildMerkleTree(8)
	var leafHash [32]byte
	copy(leafHash[:], tree.LeafHash(3))
	var forged [32]byte
	for i := range forged {
		forged[i] = 0x99
	}
	gv := merkleVerifier(t, types.TreeHead{TreeSize: 8, RootHash: forged},
		fixedTiles{did: merkleSrc, f: treeTileFetcher(tree)})
	f, _ := findings.NewCrossLogInclusionFinding(merkleSrc, 3, leafHash, 8, 1_700_000_000_000_000_000)
	if _, err := gv.Verify(context.Background(), signedEventForFinding(t, "did:relay", f)); !errors.Is(err, ErrGossipVerify) {
		t.Fatalf("forged root must be rejected, got %v", err)
	}
}

// No mirror configured ⇒ the merkle finding fails-closed (router reports the
// missing tile fetcher), never silently accepted.
func TestGossipVerifier_CrossLogInclusion_E2E_NoMirrorFailsClosed(t *testing.T) {
	tree := buildMerkleTree(8)
	var leafHash, root [32]byte
	copy(leafHash[:], tree.LeafHash(3))
	copy(root[:], tree.HashAt(8))
	gv := merkleVerifier(t, types.TreeHead{TreeSize: 8, RootHash: root}, nil)
	f, _ := findings.NewCrossLogInclusionFinding(merkleSrc, 3, leafHash, 8, 1_700_000_000_000_000_000)
	if _, err := gv.Verify(context.Background(), signedEventForFinding(t, "did:relay", f)); !errors.Is(err, ErrGossipVerify) {
		t.Fatalf("missing mirror must fail-closed, got %v", err)
	}
}

// A finding naming a source log JN has no trusted head/mirror for fails-closed.
func TestGossipVerifier_CrossLogInclusion_E2E_UnknownSourceLog(t *testing.T) {
	tree := buildMerkleTree(8)
	var leafHash, root [32]byte
	copy(leafHash[:], tree.LeafHash(3))
	copy(root[:], tree.HashAt(8))
	gv := merkleVerifier(t, types.TreeHead{TreeSize: 8, RootHash: root},
		fixedTiles{did: merkleSrc, f: treeTileFetcher(tree)})
	f, _ := findings.NewCrossLogInclusionFinding("did:web:unknown.log", 3, leafHash, 8, 1_700_000_000_000_000_000)
	if _, err := gv.Verify(context.Background(), signedEventForFinding(t, "did:relay", f)); !errors.Is(err, ErrGossipVerify) {
		t.Fatalf("unknown source log must fail-closed, got %v", err)
	}
}
