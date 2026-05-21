package crosslog

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/gossip"
	"github.com/clearcompass-ai/attesta/gossip/findings"
	"github.com/clearcompass-ai/attesta/types"
)

// testNetworkID returns a deterministic non-zero cosign NetworkID. A zero
// NetworkID is rejected by the cosign preamble, so every fixture binds to
// this value.
func testNetworkID() cosign.NetworkID {
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = byte(i + 1)
	}
	return nid
}

// sthFixture is a CosignedTreeHead plus the witness keyset that signed it.
type sthFixture struct {
	head types.CosignedTreeHead
	set  *cosign.WitnessKeySet
	nid  cosign.NetworkID
}

// makeSTHFixture builds a CosignedTreeHead signed by n witnesses bound to a
// K=n ECDSA keyset. It mirrors the SDK's own cosigned-tree-head fixture so
// the anchor consumer is exercised against the exact production cosign path
// (NewECDSAWitnessSigner.Sign over the 104-byte tree-head canonical message,
// non-zero ReceiptRoot included).
func makeSTHFixture(t *testing.T, n int) sthFixture {
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
	set, err := cosign.NewECDSAWitnessKeySet(keys, nid, n)
	if err != nil {
		t.Fatalf("NewECDSAWitnessKeySet: %v", err)
	}
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{
		TreeSize:    100,
		RootHash:    [32]byte{0xAA},
		SMTRoot:     [32]byte{0xBB},
		ReceiptRoot: [32]byte{0xCC},
	}}
	for _, s := range signers {
		sig, err := s.Sign(context.Background(), cosign.NewTreeHeadPayload(head.TreeHead), nid, cosign.HashAlgoSHA256)
		if err != nil {
			t.Fatalf("witness Sign: %v", err)
		}
		head.Signatures = append(head.Signatures, sig)
	}
	return sthFixture{head: head, set: set, nid: nid}
}

// wireBody projects a CosignedTreeHead into the gossip wire body the ledger
// embeds in a cosigned_tree_head_v1 anchor, via the SDK's own finding
// encoder (the same path the ledger publisher uses).
func wireBody(t *testing.T, head types.CosignedTreeHead, endpoint string) gossip.WireCosignedTreeHeadBody {
	t.Helper()
	f, err := findings.NewCosignedTreeHeadFinding(head, endpoint)
	if err != nil {
		t.Fatalf("NewCosignedTreeHeadFinding: %v", err)
	}
	raw, err := f.EncodeWireBody()
	if err != nil {
		t.Fatalf("EncodeWireBody: %v", err)
	}
	var w gossip.WireCosignedTreeHeadBody
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatalf("unmarshal wire body: %v", err)
	}
	return w
}

// signedEntry builds a minimal entry whose Header.SignerDID is signer, signs
// sha256(SigningPayload) with priv as a secp256k1 SigAlgoECDSA signature, and
// embeds it — exactly the production embed model. SigningPayload excludes the
// signatures section, so embedding after signing does not change the digest.
func signedEntry(t *testing.T, signer string, priv *ecdsa.PrivateKey) *envelope.Entry {
	t.Helper()
	e := &envelope.Entry{Header: envelope.ControlHeader{SignerDID: signer}}
	digest := sha256.Sum256(envelope.SigningPayload(e))
	sig, err := signatures.SignEntry(digest, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	e.Signatures = []envelope.Signature{{
		SignerDID: signer,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	return e
}

// secpKey returns a fresh secp256k1 private key and its 65-byte uncompressed
// public-key bytes (the rotation-record / initial-key wire shape).
func secpKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv, signatures.PubKeyBytes(&priv.PublicKey)
}
