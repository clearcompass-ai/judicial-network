package judicialfindings

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"
)

// testNetworkID returns a deterministic non-zero cosign NetworkID.
func testNetworkID() cosign.NetworkID {
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = byte(i + 1)
	}
	return nid
}

// witnessFixture is a K-of-N ECDSA witness keyset plus the signers behind it,
// so tests can produce real cosignatures over tree heads / escrow payloads.
type witnessFixture struct {
	set     *cosign.WitnessKeySet
	signers []cosign.WitnessSigner
	nid     cosign.NetworkID
}

func newWitnessFixture(t *testing.T, n, k int) witnessFixture {
	t.Helper()
	nid := testNetworkID()
	keys := make([]types.WitnessPublicKey, n)
	signers := make([]cosign.WitnessSigner, n)
	for i := 0; i < n; i++ {
		priv, err := signatures.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		signers[i] = cosign.NewECDSAWitnessSigner(priv)
		pub := signatures.PubKeyBytes(&priv.PublicKey)
		keys[i] = types.WitnessPublicKey{ID: sha256.Sum256(pub), PublicKey: pub, SchemeTag: signatures.SchemeECDSA}
	}
	set, err := cosign.NewECDSAWitnessKeySet(keys, nid, k)
	if err != nil {
		t.Fatalf("NewECDSAWitnessKeySet: %v", err)
	}
	return witnessFixture{set: set, signers: signers, nid: nid}
}

// newTestWitnessSet is the keyset-only convenience used where signers aren't needed.
func newTestWitnessSet(t *testing.T, n, k int) *cosign.WitnessKeySet {
	return newWitnessFixture(t, n, k).set
}

// cosignedHead builds a CosignedTreeHead at (treeSize, rootHash) signed by
// every witness in the fixture.
func (wf witnessFixture) cosignedHead(t *testing.T, treeSize uint64, rootHash [32]byte) types.CosignedTreeHead {
	t.Helper()
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{
		TreeSize:    treeSize,
		RootHash:    rootHash,
		SMTRoot:     [32]byte{0xBB},
		ReceiptRoot: [32]byte{0xCC},
	}}
	for _, s := range wf.signers {
		sig, err := s.Sign(context.Background(), cosign.NewTreeHeadPayload(head.TreeHead), wf.nid, cosign.HashAlgoSHA256)
		if err != nil {
			t.Fatalf("witness Sign: %v", err)
		}
		head.Signatures = append(head.Signatures, sig)
	}
	return head
}

// cosignEscrow signs an EscrowOverridePayload with every witness in the
// fixture (under PurposeEscrowOverride, which the payload pins).
func (wf witnessFixture) cosignEscrow(t *testing.T, p cosign.EscrowOverridePayload) []types.WitnessSignature {
	t.Helper()
	sigs := make([]types.WitnessSignature, 0, len(wf.signers))
	for _, s := range wf.signers {
		sig, err := s.Sign(context.Background(), p, wf.nid, cosign.HashAlgoSHA256)
		if err != nil {
			t.Fatalf("escrow Sign: %v", err)
		}
		sigs = append(sigs, sig)
	}
	return sigs
}
