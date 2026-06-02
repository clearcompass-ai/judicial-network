package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/cosign"
	sdksigs "github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/network"

	"github.com/clearcompass-ai/attesta-tools/libs/crosslog"
)

const blsPeerLogDID = "did:web:state:tn:williamson"

// buildBLSDeclarationEntry mints a real BLS-G2 witness key, builds + signs a
// WitnessEndpointDeclaration entry carrying its 96-byte compressed key + 48-byte
// proof-of-possession, and returns the canonical envelope wire bytes plus the
// witness PubKeyID, public key, and PoP for assertions.
func buildBLSDeclarationEntry(t *testing.T) (wire []byte, pubKeyID [32]byte, pubKey, pop []byte) {
	t.Helper()
	priv, pub, err := sdksigs.GenerateBLSKey()
	if err != nil {
		t.Fatalf("GenerateBLSKey: %v", err)
	}
	pubKey = sdksigs.BLSPubKeyBytes(pub)
	pop, err = sdksigs.SignBLSPoP(pub, priv)
	if err != nil {
		t.Fatalf("SignBLSPoP: %v", err)
	}
	pubKeyID = sha256.Sum256(pubKey)

	decl := network.WitnessEndpointDeclaration{
		PubKeyID:          pubKeyID,
		Endpoints:         map[string]string{"AttestaWitness": "https://w.example.org/v1/cosign"},
		SchemeTag:         sdksigs.SchemeBLS,
		PublicKey:         pubKey,
		ProofOfPossession: pop,
	}
	payload, err := network.EncodeWitnessEndpointDeclarationPayload(decl)
	if err != nil {
		t.Fatalf("EncodeWitnessEndpointDeclarationPayload: %v", err)
	}

	unsigned, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   "did:key:zWitness",
		Destination: blsPeerLogDID,
	}, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	k, err := sdksigs.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := sha256.Sum256(envelope.SigningPayload(unsigned))
	sig, err := sdksigs.SignEntry(digest, k)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	signed, err := envelope.NewEntry(unsigned.Header, unsigned.DomainPayload, []envelope.Signature{
		{SignerDID: unsigned.Header.SignerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig},
	})
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	wire, err = envelope.Serialize(signed)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return wire, pubKeyID, pubKey, pop
}

// writeSnapshot writes a one-entry declaration snapshot at seq and returns its path.
func writeSnapshot(t *testing.T, wire []byte, seq uint64) string {
	t.Helper()
	rows := []witnessDeclSnapshotEntry{{
		LogDID:   blsPeerLogDID,
		Sequence: seq,
		EntryB64: base64.StdEncoding.EncodeToString(wire),
	}}
	b, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	p := filepath.Join(t.TempDir(), "witness-declarations.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	return p
}

// TestSourceBLSWitnesses_ProjectsAuthorizedAndBuildsSet is the end-to-end pin:
// a real on-log BLS WitnessEndpointDeclaration snapshot → projected for the
// AUTHORIZED PubKeyID → folded into a WitnessSetSpec that
// BuildWitnessSetsForPolicy builds under a BLS-admitting policy. The PoP is
// verified at cosign.NewWitnessKeySet construction, so a clean build proves the
// projected key material is cryptographically sound (a forged PoP fails here).
func TestSourceBLSWitnesses_ProjectsAuthorizedAndBuildsSet(t *testing.T) {
	wire, pubKeyID, pubKey, pop := buildBLSDeclarationEntry(t)
	snap := writeSnapshot(t, wire, 7)
	authorized := []string{hex.EncodeToString(pubKeyID[:])}

	bls, err := sourceBLSWitnesses(blsPeerLogDID, snap, authorized)
	if err != nil {
		t.Fatalf("sourceBLSWitnesses: %v", err)
	}
	if len(bls) != 1 {
		t.Fatalf("projected %d BLS witnesses, want 1", len(bls))
	}
	if bls[0].ID != pubKeyID {
		t.Fatalf("projected ID = %x, want %x", bls[0].ID, pubKeyID)
	}
	if !bytes.Equal(bls[0].PublicKey, pubKey) || !bytes.Equal(bls[0].ProofOfPossession, pop) {
		t.Fatal("projected key/PoP bytes do not match the on-log declaration")
	}

	// Fold into a spec + build the set under a BLS-admitting policy. A BLS-only
	// set (no ECDSA did:keys) is the cleanest proof the projected key alone
	// constructs a valid quorum; NewWitnessKeySet verifies the PoP here.
	var nid cosign.NetworkID
	for i := range nid {
		nid[i] = byte(i + 1)
	}
	spec := crosslog.WitnessSetSpec{LogDID: blsPeerLogDID, BLSWitnesses: bls, QuorumK: 1}
	sets, err := crosslog.BuildWitnessSetsForPolicy([]crosslog.WitnessSetSpec{spec}, nid,
		[]uint8{sdksigs.SchemeECDSA, sdksigs.SchemeBLS})
	if err != nil {
		t.Fatalf("BuildWitnessSetsForPolicy (BLS-admitting) rejected the PoP-verified set: %v", err)
	}
	ks := sets[blsPeerLogDID]
	if ks == nil {
		t.Fatal("no keyset built for the peer log")
	}
	if ks.BLSVerifier() == nil {
		t.Fatal("BLS-admitting policy must wire a BLS aggregate verifier")
	}
}

// TestSourceBLSWitnesses_UnauthorizedIDNotProjected pins the membership
// authority: a declaration whose PubKeyID is NOT in AuthorizedBLSWitnessIDs is
// never projected — a rogue self-asserted BLS declaration cannot inject itself
// into the quorum (crosslog.BLSWitnessesFromDeclarations does not derive the
// authorized set from the declarations).
func TestSourceBLSWitnesses_UnauthorizedIDNotProjected(t *testing.T) {
	wire, _, _, _ := buildBLSDeclarationEntry(t)
	snap := writeSnapshot(t, wire, 7)

	other := make([]byte, 32)
	other[0] = 0xAA // an id that is NOT the declaration's PubKeyID
	bls, err := sourceBLSWitnesses(blsPeerLogDID, snap, []string{hex.EncodeToString(other)})
	if err != nil {
		t.Fatalf("sourceBLSWitnesses: %v", err)
	}
	if len(bls) != 0 {
		t.Fatalf("projected %d BLS witnesses for an unauthorized ID, want 0", len(bls))
	}
}

// TestWitnessSpecWithBLS_NoSnapshotIsECDSAOnly pins the default: with no
// declarations file the spec is exactly the prior ECDSA-only shape (nil
// BLSWitnesses), so existing deployments are byte-identical.
func TestWitnessSpecWithBLS_NoSnapshotIsECDSAOnly(t *testing.T) {
	spec, err := witnessSpecWithBLS(blsPeerLogDID, []string{"did:key:zW1"}, 1, "", nil)
	if err != nil {
		t.Fatalf("witnessSpecWithBLS: %v", err)
	}
	if spec.BLSWitnesses != nil {
		t.Fatalf("expected nil BLSWitnesses with no snapshot, got %d", len(spec.BLSWitnesses))
	}
	if spec.LogDID != blsPeerLogDID || len(spec.WitnessDIDs) != 1 || spec.QuorumK != 1 {
		t.Fatal("ECDSA-only spec fields not preserved")
	}
}

// TestSourceBLSWitnesses_RejectsBadAuthorizedID pins input validation: a
// non-hex or wrong-length authorized id is a loud config error, not a silent
// skip.
func TestSourceBLSWitnesses_RejectsBadAuthorizedID(t *testing.T) {
	wire, _, _, _ := buildBLSDeclarationEntry(t)
	snap := writeSnapshot(t, wire, 7)
	if _, err := sourceBLSWitnesses(blsPeerLogDID, snap, []string{"zz"}); err == nil {
		t.Fatal("expected error for a non-hex authorized id")
	}
}
