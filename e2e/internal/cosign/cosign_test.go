package cosign

import (
	"crypto/ecdsa"
	"encoding/hex"
	"strings"
	"testing"

	sdkcosign "github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/did"
	sdknetwork "github.com/baseproof/baseproof/network"
	baseprooftypes "github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	"github.com/clearcompass-ai/judicial-network/e2e/internal/types"
)

// TestVerify_RealCosignedHead proves the H5 wiring end-to-end, OFFLINE: build a
// genesis witness set as did:key DIDs, derive the NetworkID exactly as the SDK
// does (bootstrap.IDs), cosign a tree head under it with K witnesses, then
// confirm cosign.Verify recomputes K valid signatures — and that tampering one
// signature drops below quorum. No stack required.
func TestVerify_RealCosignedHead(t *testing.T) {
	const n, k = 4, 3

	dids := make([]string, n)
	privs := make([]*ecdsa.PrivateKey, n)
	for i := 0; i < n; i++ {
		pair, err := did.GenerateDIDKeySecp256k1()
		if err != nil {
			t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
		}
		dids[i] = pair.DID
		privs[i] = pair.PrivateKey
	}

	// NetworkID exactly as the SDK derives it from the canonical bootstrap —
	// the same path internal/bootstrap.Load uses.
	nb := sdknetwork.BootstrapDocument{
		ProtocolVersion:   "baseproof/v1",
		ExchangeDID:       "did:web:cosign.test",
		NetworkName:       "cosign-test",
		GenesisWitnessSet: dids,
		GenesisTreeHead:   sdknetwork.GenesisTreeHead{RootHash: strings.Repeat("0", 64), TreeSize: 0},
		// A valid (gating-off) genesis policy so the doc canonicalizes; the
		// admission config doesn't affect the witness NetworkID derivation.
		GenesisAdmissionPolicy: sdknetwork.GenesisAdmissionPolicy{GatingRequired: false, CostMode: "uncharged"},
		// secp256k1-ECDSA (0x0001) — the zero-trust default entry sig scheme.
		GenesisSignaturePolicy: sdknetwork.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{0x0001},
			AllowedCosignSchemeTags: []uint8{0x01},
			MinSignaturesPerEntry:   1,
		},
	}
	ids, err := nb.IDs()
	if err != nil {
		t.Fatalf("bootstrap IDs(): %v", err)
	}
	networkID := ids.NetworkID

	// Witness key IDs as the verifier reconstructs them from the DIDs — used as
	// the cosignature PubKeyIDs so they match by construction.
	keys, err := witness.KeysFromDIDs(dids)
	if err != nil {
		t.Fatalf("KeysFromDIDs: %v", err)
	}

	// Cosign a head with K of the N witnesses, under the NetworkID.
	head := baseprooftypes.TreeHead{RootHash: fill(0xA1), SMTRoot: fill(0xB2), TreeSize: 7}
	payload := sdkcosign.NewTreeHeadPayload(head)
	sigs := make([]baseprooftypes.WitnessSignature, 0, k)
	for i := 0; i < k; i++ {
		sb, serr := sdkcosign.SignECDSA(payload, networkID, sdkcosign.HashAlgoSHA256, privs[i])
		if serr != nil {
			t.Fatalf("SignECDSA %d: %v", i, serr)
		}
		sigs = append(sigs, baseprooftypes.WitnessSignature{
			PubKeyID: keys[i].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sb,
		})
	}

	boot := types.BootstrapDocument{GenesisWitnessSet: dids, NetworkID: [32]byte(networkID)}

	// Happy path: the wiring recomputes exactly K valid signatures.
	res, err := Verify(boot, k, toWireHead(head, sigs))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.ValidCount != k {
		t.Fatalf("ValidCount=%d, want %d (total=%d)", res.ValidCount, k, res.Total)
	}

	// Tamper one signature → below quorum.
	bad := toWireHead(head, sigs)
	bad.Signatures[0].SigBytes = flipHex(bad.Signatures[0].SigBytes)
	if res2, _ := Verify(boot, k, bad); res2.ValidCount >= k {
		t.Fatalf("tampered head still reached quorum (ValidCount=%d)", res2.ValidCount)
	}

	// Sanity: Wired() reports true now that the real verifier is installed.
	if !Wired() {
		t.Fatal("Wired() = false after wiring the SDK verifier")
	}
}

func fill(b byte) [32]byte {
	var r [32]byte
	for i := range r {
		r[i] = b
	}
	return r
}

func toWireHead(h baseprooftypes.TreeHead, sigs []baseprooftypes.WitnessSignature) types.CosignedTreeHead {
	w := types.CosignedTreeHead{
		RootHash:    hex.EncodeToString(h.RootHash[:]),
		SMTRoot:     hex.EncodeToString(h.SMTRoot[:]),
		ReceiptRoot: hex.EncodeToString(h.ReceiptRoot[:]),
		TreeSize:    h.TreeSize,
	}
	for _, s := range sigs {
		w.Signatures = append(w.Signatures, types.WitnessSignature{
			PubKeyID:  hex.EncodeToString(s.PubKeyID[:]),
			SchemeTag: uint(s.SchemeTag),
			SigBytes:  hex.EncodeToString(s.SigBytes),
		})
	}
	return w
}

func flipHex(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) == 0 {
		return s
	}
	b[0] ^= 0xFF
	return hex.EncodeToString(b)
}
