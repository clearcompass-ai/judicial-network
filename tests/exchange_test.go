/*
FILE PATH: tests/exchange_test.go

Tests for exchange/ — auth (mTLS + signed requests), keystore,
entry build/sign/submit, artifact publish/grant, index scanner/store.
*/
package tests

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/signatures"

	"github.com/clearcompass-ai/judicial-network/api/exchange/auth"
	"github.com/clearcompass-ai/judicial-network/api/exchange/index"
	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
)

// ─── mTLS Auth ──────────────────────────────────────────────────────

func TestMTLS_ExtractDIDFromCert(t *testing.T) {
	didURI, _ := url.Parse("did:web:courts.nashville.gov:role:judge-mcclendon")
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "judge-mcclendon"},
		URIs:    []*url.URL{didURI},
	}

	got := auth.ExtractDIDFromCert(cert)
	want := "did:web:courts.nashville.gov:role:judge-mcclendon"
	if got != want {
		t.Errorf("ExtractDIDFromCert = %q, want %q", got, want)
	}
}

func TestMTLS_ExtractDIDFromCert_NoDIDSAN(t *testing.T) {
	nonDIDURI, _ := url.Parse("https://courts.nashville.gov")
	cert := &x509.Certificate{
		URIs: []*url.URL{nonDIDURI},
	}

	got := auth.ExtractDIDFromCert(cert)
	if got != "" {
		t.Errorf("ExtractDIDFromCert = %q, want empty", got)
	}
}

func TestMTLS_ExtractDIDFromCert_NilCert(t *testing.T) {
	got := auth.ExtractDIDFromCert(nil)
	if got != "" {
		t.Errorf("ExtractDIDFromCert(nil) = %q, want empty", got)
	}
}

func TestMTLS_BuildCertSAN(t *testing.T) {
	uri, err := auth.BuildCertSAN("did:web:courts.nashville.gov")
	if err != nil {
		t.Fatalf("BuildCertSAN failed: %v", err)
	}
	if uri.String() != "did:web:courts.nashville.gov" {
		t.Errorf("BuildCertSAN = %q, want did:web:courts.nashville.gov", uri.String())
	}
}

func TestMTLS_BuildCertSAN_InvalidDID(t *testing.T) {
	_, err := auth.BuildCertSAN("not-a-did")
	if err == nil {
		t.Fatal("Expected error for non-DID string")
	}
}

// ─── Signed Request Auth ────────────────────────────────────────────

func TestSignedRequest_NonceStore_Fresh(t *testing.T) {
	ns := auth.NewNonceStore(5 * time.Minute)

	ok := ns.Check("nonce-1", time.Now())
	if !ok {
		t.Fatal("Fresh nonce should pass")
	}
}

func TestSignedRequest_NonceStore_Replay(t *testing.T) {
	ns := auth.NewNonceStore(5 * time.Minute)

	ns.Check("nonce-1", time.Now())
	ok := ns.Check("nonce-1", time.Now())
	if ok {
		t.Fatal("Replayed nonce should fail")
	}
}

func TestSignedRequest_NonceStore_Expired(t *testing.T) {
	ns := auth.NewNonceStore(5 * time.Minute)

	// Timestamp older than window.
	ok := ns.Check("nonce-old", time.Now().Add(-10*time.Minute))
	if ok {
		t.Fatal("Expired timestamp should fail")
	}
}

func TestSignedRequest_VerifySignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	req := &auth.SignedRequest{
		SignerDID: "did:web:test:signer",
		Action:    "build_and_sign",
		Payload:   json.RawMessage(`{"builder":"amendment"}`),
		Timestamp: time.Now().UTC(),
		Nonce:     "test-nonce-123",
	}

	// Sign the canonical form.
	canonical := fmt.Sprintf("%s|%s|%s|%s|%s",
		req.SignerDID, req.Action, string(req.Payload),
		req.Timestamp.Format(time.RFC3339Nano), req.Nonce)
	req.Signature = ed25519.Sign(priv, []byte(canonical))

	err := auth.VerifySignedRequest(req, pub)
	if err != nil {
		t.Fatalf("VerifySignedRequest failed: %v", err)
	}
}

func TestSignedRequest_InvalidSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)

	req := &auth.SignedRequest{
		SignerDID: "did:web:test:signer",
		Action:    "build_and_sign",
		Payload:   json.RawMessage(`{}`),
		Timestamp: time.Now().UTC(),
		Nonce:     "test-nonce",
		Signature: []byte("definitely-not-valid"),
	}

	err := auth.VerifySignedRequest(req, pub)
	if err == nil {
		t.Fatal("Expected error for invalid signature")
	}
}

// ─── KeyStore ───────────────────────────────────────────────────────

func TestKeyStore_Generate(t *testing.T) {
	ks := keystore.NewMemoryKeyStore()
	info, err := ks.Generate("did:web:test:judge", "signing")
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if info.DID != "did:web:test:judge" {
		t.Errorf("DID = %q, want did:web:test:judge", info.DID)
	}
	if info.Purpose != "signing" {
		t.Errorf("Purpose = %q, want signing", info.Purpose)
	}
	if len(info.PublicKey) != 65 || info.PublicKey[0] != 0x04 {
		t.Errorf("PublicKey shape = len %d prefix %#x, want 65/0x04 (uncompressed secp256k1)",
			len(info.PublicKey), info.PublicKey[0])
	}
}

func TestKeyStore_SignEntry(t *testing.T) {
	ks := keystore.NewMemoryKeyStore()
	info, _ := ks.Generate("did:web:test:signer", "signing")

	digest := sha256.Sum256([]byte("test entry signing payload"))
	sig, err := ks.SignEntry("did:web:test:signer", digest)
	if err != nil {
		t.Fatalf("SignEntry failed: %v", err)
	}
	pub, err := signatures.ParsePubKey(info.PublicKey)
	if err != nil {
		t.Fatalf("ParsePubKey: %v", err)
	}
	if err := signatures.VerifyEntry(digest, sig, pub); err != nil {
		t.Fatalf("VerifyEntry rejected SignEntry signature: %v", err)
	}
}

func TestKeyStore_Sign_UnknownDID(t *testing.T) {
	ks := keystore.NewMemoryKeyStore()
	if _, err := ks.SignEntry("did:web:nonexistent", [32]byte{}); err == nil {
		t.Fatal("Expected error for unknown DID")
	}
}

func TestKeyStore_StagedRotation(t *testing.T) {
	ks := keystore.NewMemoryKeyStore()
	original, _ := ks.Generate("did:web:test:rotate", "signing")
	digest := sha256.Sum256([]byte("rotation entry"))

	staged, err := ks.StageNextKey("did:web:test:rotate", 1)
	if err != nil {
		t.Fatalf("StageNextKey failed: %v", err)
	}
	if string(staged.PublicKey) == string(original.PublicKey) {
		t.Error("staged key should differ from original")
	}

	// Pre-commit: the OLD key still signs (old-key-signs).
	sig, _ := ks.SignEntry("did:web:test:rotate", digest)
	oldPK, _ := signatures.ParsePubKey(original.PublicKey)
	if err := signatures.VerifyEntry(digest, sig, oldPK); err != nil {
		t.Errorf("pre-commit signature must verify under the OLD key: %v", err)
	}

	// Post-commit: the new key is active.
	if _, err := ks.CommitRotation("did:web:test:rotate"); err != nil {
		t.Fatalf("CommitRotation failed: %v", err)
	}
	sig2, _ := ks.SignEntry("did:web:test:rotate", digest)
	newPK, _ := signatures.ParsePubKey(staged.PublicKey)
	if err := signatures.VerifyEntry(digest, sig2, newPK); err != nil {
		t.Errorf("post-commit signature must verify under the NEW key: %v", err)
	}
}

func TestKeyStore_Destroy(t *testing.T) {
	ks := keystore.NewMemoryKeyStore()
	ks.Generate("did:web:test:destroy", "signing")

	if err := ks.Destroy("did:web:test:destroy"); err != nil {
		t.Fatalf("Destroy failed: %v", err)
	}
	if _, err := ks.SignEntry("did:web:test:destroy", [32]byte{}); err == nil {
		t.Fatal("Expected error after Destroy")
	}
}

func TestKeyStore_ExportForEscrow(t *testing.T) {
	ks := keystore.NewMemoryKeyStore()
	ks.Generate("did:web:test:escrow", "signing")

	priv, err := ks.ExportForEscrow("did:web:test:escrow")
	if err != nil {
		t.Fatalf("ExportForEscrow failed: %v", err)
	}
	if len(priv) != 32 {
		t.Errorf("Private key length = %d, want 32 (secp256k1 scalar)", len(priv))
	}
}

func TestKeyStore_List(t *testing.T) {
	ks := keystore.NewMemoryKeyStore()
	ks.Generate("did:web:key1", "signing")
	ks.Generate("did:web:key2", "encryption")

	keys := ks.List()
	if len(keys) != 2 {
		t.Errorf("List returned %d keys, want 2", len(keys))
	}
}

// ─── Index Store ────────────────────────────────────────────────────

func TestIndex_DocketMapping(t *testing.T) {
	store := index.NewIndexStore()

	store.AddDocketMapping("cases-log", "2027-CR-4471", 100)
	store.AddDocketMapping("cases-log", "2027-CR-4471", 200)
	store.AddDocketMapping("cases-log", "2027-CV-1234", 300)

	positions := store.LookupDocket("cases-log", "2027-CR-4471")
	if len(positions) != 2 {
		t.Errorf("LookupDocket returned %d positions, want 2", len(positions))
	}
	if positions[0] != 100 || positions[1] != 200 {
		t.Errorf("Positions = %v, want [100 200]", positions)
	}

	// Different docket.
	positions2 := store.LookupDocket("cases-log", "2027-CV-1234")
	if len(positions2) != 1 || positions2[0] != 300 {
		t.Errorf("LookupDocket 2027-CV-1234 = %v, want [300]", positions2)
	}
}

func TestIndex_DocketMapping_WrongLog(t *testing.T) {
	store := index.NewIndexStore()
	store.AddDocketMapping("log-a", "docket-1", 100)

	positions := store.LookupDocket("log-b", "docket-1")
	if len(positions) != 0 {
		t.Errorf("LookupDocket on wrong log returned %d, want 0", len(positions))
	}
}

func TestIndex_CIDMapping(t *testing.T) {
	store := index.NewIndexStore()
	store.AddCIDMapping("cases-log", "bafy123", 500)

	pos, found := store.LookupCID("cases-log", "bafy123")
	if !found {
		t.Fatal("CID not found")
	}
	if pos != 500 {
		t.Errorf("CID position = %d, want 500", pos)
	}
}

func TestIndex_CIDMapping_NotFound(t *testing.T) {
	store := index.NewIndexStore()
	_, found := store.LookupCID("cases-log", "nonexistent")
	if found {
		t.Fatal("Expected not found for missing CID")
	}
}

func TestIndex_DIDMapping(t *testing.T) {
	store := index.NewIndexStore()
	store.AddDIDMapping("officers-log", "did:web:judge", 10)
	store.AddDIDMapping("officers-log", "did:web:judge", 20)

	positions := store.LookupDID("officers-log", "did:web:judge")
	if len(positions) != 2 {
		t.Errorf("DID positions = %d, want 2", len(positions))
	}
}

func TestIndex_PartyMapping(t *testing.T) {
	store := index.NewIndexStore()
	store.AddPartyMapping("parties-log", "John Smith", 50)

	positions := store.LookupParty("parties-log", "John Smith")
	if len(positions) != 1 || positions[0] != 50 {
		t.Errorf("Party positions = %v, want [50]", positions)
	}
}

func TestIndex_ScanPosition(t *testing.T) {
	store := index.NewIndexStore()
	store.SetLastScannedPosition("log-a", 1000)

	pos := store.LastScannedPosition("log-a")
	if pos != 1000 {
		t.Errorf("LastScannedPosition = %d, want 1000", pos)
	}
}

func TestIndex_ScanPosition_Default(t *testing.T) {
	store := index.NewIndexStore()
	pos := store.LastScannedPosition("never-scanned")
	if pos != 0 {
		t.Errorf("Default LastScannedPosition = %d, want 0", pos)
	}
}
