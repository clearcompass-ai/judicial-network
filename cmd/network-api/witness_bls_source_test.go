package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdksigs "github.com/baseproof/baseproof/crypto/signatures"

	"github.com/clearcompass-ai/attesta-tools/libs/crosslog"
)

const blsPeerLogDID = "did:web:state:tn:williamson"

// blsDeclFixture mints a real BLS-G2 witness and returns its declaration-file
// JSON row (hex key material) plus its PubKeyID / public key / PoP.
func blsDeclFixture(t *testing.T, seq uint64) (row witnessEndpointDeclJSON, id [32]byte, pub, pop []byte) {
	t.Helper()
	priv, g2, err := sdksigs.GenerateBLSKey()
	if err != nil {
		t.Fatalf("GenerateBLSKey: %v", err)
	}
	pub = sdksigs.BLSPubKeyBytes(g2)
	pop, err = sdksigs.SignBLSPoP(g2, priv)
	if err != nil {
		t.Fatalf("SignBLSPoP: %v", err)
	}
	id = sha256.Sum256(pub)
	return witnessEndpointDeclJSON{
		EffectiveSeq:      seq,
		PubKeyID:          hex.EncodeToString(id[:]),
		Endpoints:         map[string]string{"BaseproofWitness": "https://w.example.org/v1/cosign"},
		SchemeTag:         sdksigs.SchemeBLS,
		PublicKey:         hex.EncodeToString(pub),
		ProofOfPossession: hex.EncodeToString(pop),
	}, id, pub, pop
}

func writeDeclFile(t *testing.T, rows ...witnessEndpointDeclJSON) string {
	t.Helper()
	b, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("marshal declaration file: %v", err)
	}
	p := filepath.Join(t.TempDir(), "witness-declarations.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write declaration file: %v", err)
	}
	return p
}

// TestSourceBLSWitnesses_ProjectsAuthorizedAndBuildsSet is the end-to-end pin:
// an operator declaration file → the shared crosslog builders → projected BLS
// witness → BuildWitnessSetsForPolicy builds the set with a BLS verifier (the
// PoP is verified at cosign.NewWitnessKeySet construction, so a clean build
// proves the projected key material is sound).
func TestSourceBLSWitnesses_ProjectsAuthorizedAndBuildsSet(t *testing.T) {
	decl, id, pub, pop := blsDeclFixture(t, 7)
	file := writeDeclFile(t, decl)
	authorized := []string{hex.EncodeToString(id[:])}

	bls, err := sourceBLSWitnesses(blsPeerLogDID, file, authorized)
	if err != nil {
		t.Fatalf("sourceBLSWitnesses: %v", err)
	}
	if len(bls) != 1 || bls[0].ID != id {
		t.Fatalf("projected %d witnesses, want the one BLS witness %x", len(bls), id)
	}
	if !bytes.Equal(bls[0].PublicKey, pub) || !bytes.Equal(bls[0].ProofOfPossession, pop) {
		t.Fatal("projected key/PoP bytes do not match the declaration")
	}

	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = byte(i + 1)
	}
	spec := crosslog.WitnessSetSpec{LogDID: blsPeerLogDID, BLSWitnesses: bls, QuorumK: 1}
	sets, err := crosslog.BuildWitnessSetsForPolicy([]crosslog.WitnessSetSpec{spec}, nid,
		[]uint8{sdksigs.SchemeECDSA, sdksigs.SchemeBLS})
	if err != nil {
		t.Fatalf("BuildWitnessSetsForPolicy rejected the PoP-verified set: %v", err)
	}
	ks := sets[blsPeerLogDID]
	if ks == nil || ks.BLSVerifier() == nil {
		t.Fatal("expected a BLS-verifying keyset")
	}
}

// TestSourceBLSWitnesses_UnauthorizedIDNotProjected pins the membership
// authority: a declaration whose PubKeyID is not in the authorized set is never
// projected — a rogue declaration cannot inject itself into the quorum.
func TestSourceBLSWitnesses_UnauthorizedIDNotProjected(t *testing.T) {
	decl, _, _, _ := blsDeclFixture(t, 7)
	file := writeDeclFile(t, decl)

	other := make([]byte, 32)
	other[0] = 0xAA
	bls, err := sourceBLSWitnesses(blsPeerLogDID, file, []string{hex.EncodeToString(other)})
	if err != nil {
		t.Fatalf("sourceBLSWitnesses: %v", err)
	}
	if len(bls) != 0 {
		t.Fatalf("projected %d witnesses for an unauthorized id, want 0", len(bls))
	}
}

// TestWitnessSpecWithBLS_NoFileIsECDSAOnly pins the default: with no declaration
// file the spec is exactly the prior ECDSA-only shape (nil BLSWitnesses).
func TestWitnessSpecWithBLS_NoFileIsECDSAOnly(t *testing.T) {
	spec, err := witnessSpecWithBLS(blsPeerLogDID, []string{"did:key:zW1"}, 1, "", nil)
	if err != nil {
		t.Fatalf("witnessSpecWithBLS: %v", err)
	}
	if spec.BLSWitnesses != nil {
		t.Fatalf("expected nil BLSWitnesses with no file, got %d", len(spec.BLSWitnesses))
	}
	if spec.LogDID != blsPeerLogDID || len(spec.WitnessDIDs) != 1 || spec.QuorumK != 1 {
		t.Fatal("ECDSA-only spec fields not preserved")
	}
}

// TestSourceBLSWitnesses_RejectsBadDeclaration confirms each row is validated by
// the shared builder (incl. SHA-256(PublicKey)==PubKeyID for BLS): a corrupted
// PubKeyID is a loud boot error, not a silent skip.
func TestSourceBLSWitnesses_RejectsBadDeclaration(t *testing.T) {
	decl, id, _, _ := blsDeclFixture(t, 7)
	bad := id
	bad[0] ^= 0xFF // break the PublicKey↔PubKeyID binding
	decl.PubKeyID = hex.EncodeToString(bad[:])
	file := writeDeclFile(t, decl)

	if _, err := sourceBLSWitnesses(blsPeerLogDID, file, []string{hex.EncodeToString(bad[:])}); err == nil {
		t.Fatal("expected validation rejection for PubKeyID/key mismatch")
	}
}
