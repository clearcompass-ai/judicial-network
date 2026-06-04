// Package equivocation is the H4 fork-injection fixture (gap G1): a controllable
// byzantine witness set that cosigns TWO divergent tree heads at the SAME tree
// size — a provable log fork — plus the honest controls.
//
// It is PURE SDK: real secp256k1 K-of-N cosignatures over two different RFC-6962
// roots at one tree size — exactly what witness.DetectEquivocation consumes
// (baseproof/witness/equivocation.go). "Physics, not mocks." Because it needs NO
// live infrastructure, `go test ./equivocation/` runs the whole
// equivocation → finding → position-aware → burn-gate chain on a developer
// desktop with no stack provisioned.
//
// SEGMENTATION (per the test taxonomy): this package is the SDK-level tier. The
// e2e black-box suite (tests/, build tag `e2e`) CAPTURES the same assertions via
// tests/phase6_equivocation_capture_test.go, so a single `make test` run against
// the live federation exercises them too. The only piece that genuinely needs a
// spun-up stack is injecting the fork into a RUNNING auditor (S6.7, behind
// E2E_FORK_ENABLE) — everything else here is infra-free.
package equivocation

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
)

// WitnessSet is a controllable k-of-n witness quorum: the verifier-facing
// *cosign.WitnessKeySet plus the private keys, so the fixture can cosign heads
// the way a real witness fleet does.
type WitnessSet struct {
	Set       *cosign.WitnessKeySet
	Keys      []types.WitnessPublicKey
	Privs     []*ecdsa.PrivateKey
	NetworkID cosign.NetworkID
	N, K      int
}

// NetworkIDFromLabel derives a deterministic NetworkID from a label so a fixture
// is reproducible across runs.
func NetworkIDFromLabel(label string) cosign.NetworkID {
	return cosign.NetworkID(sha256.Sum256([]byte(label)))
}

// NewWitnessSet generates n secp256k1 witness identities and assembles a
// k-of-n *cosign.WitnessKeySet bound to networkID — the genuine cosign machinery
// (NOT a stub), so heads it signs verify under the real cosign.Verify path.
func NewWitnessSet(n, k int, networkID cosign.NetworkID) (*WitnessSet, error) {
	if k < 1 || k > n {
		return nil, fmt.Errorf("equivocation: invalid quorum k=%d of n=%d", k, n)
	}
	keys := make([]types.WitnessPublicKey, n)
	privs := make([]*ecdsa.PrivateKey, n)
	for i := 0; i < n; i++ {
		priv, err := signatures.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("equivocation: GenerateKey %d: %w", i, err)
		}
		pub := signatures.PubKeyBytes(&priv.PublicKey)
		keys[i] = types.WitnessPublicKey{ID: sha256.Sum256(pub), PublicKey: pub, SchemeTag: signatures.SchemeECDSA}
		privs[i] = priv
	}
	set, err := cosign.NewWitnessKeySet(keys, networkID, k, nil)
	if err != nil {
		return nil, fmt.Errorf("equivocation: NewWitnessKeySet: %w", err)
	}
	return &WitnessSet{Set: set, Keys: keys, Privs: privs, NetworkID: networkID, N: n, K: k}, nil
}

// CosignHead produces a tree head at `size` with the given roots, cosigned by the
// first `sigCount` witnesses. sigCount >= K yields a valid quorum head; sigCount
// < K is a deliberately sub-quorum head (used by the no-false-slash control).
func (ws *WitnessSet) CosignHead(size uint64, root, smtRoot [32]byte, sigCount int) (types.CosignedTreeHead, error) {
	head := types.TreeHead{RootHash: root, SMTRoot: smtRoot, ReceiptRoot: [32]byte{}, TreeSize: size}
	payload := cosign.NewTreeHeadPayload(head)
	sigs := make([]types.WitnessSignature, 0, sigCount)
	for i := 0; i < sigCount && i < ws.N; i++ {
		sb, err := cosign.SignECDSA(payload, ws.NetworkID, cosign.HashAlgoSHA256, ws.Privs[i])
		if err != nil {
			return types.CosignedTreeHead{}, fmt.Errorf("equivocation: SignECDSA witness %d: %w", i, err)
		}
		sigs = append(sigs, types.WitnessSignature{PubKeyID: ws.Keys[i].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sb})
	}
	return types.CosignedTreeHead{TreeHead: head, Signatures: sigs}, nil
}

// fill returns a non-zero 32-byte root. cosign's dual-commitment binding rejects
// an all-zero RootHash/SMTRoot, so heads must carry non-zero roots.
func fill(b byte) [32]byte {
	var r [32]byte
	for i := range r {
		r[i] = b
	}
	return r
}

// Fork is THE H4 fixture: two heads at the SAME tree size with DIFFERENT roots,
// BOTH validly K-of-N cosigned by the same set — an unforgeable log fork.
func (ws *WitnessSet) Fork(size uint64) (headA, headB types.CosignedTreeHead, err error) {
	headA, err = ws.CosignHead(size, fill(0xA1), fill(0xA2), ws.N)
	if err != nil {
		return
	}
	headB, err = ws.CosignHead(size, fill(0xB1), fill(0xB2), ws.N)
	return
}

// HonestPair is the no-equivocation control: two heads at the same size with the
// SAME root (a witness fleet re-publishing one head). DetectEquivocation must
// return (nil, nil) for this — anything else is a false slash.
func (ws *WitnessSet) HonestPair(size uint64) (headA, headB types.CosignedTreeHead, err error) {
	headA, err = ws.CosignHead(size, fill(0xC1), fill(0xC2), ws.N)
	if err != nil {
		return
	}
	headB, err = ws.CosignHead(size, fill(0xC1), fill(0xC2), ws.N)
	return
}
