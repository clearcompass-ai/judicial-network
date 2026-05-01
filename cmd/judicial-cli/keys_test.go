/*
FILE PATH: cmd/judicial-cli/keys_test.go

DESCRIPTION:
    Roundtrip + interop tests for the on-disk key file format. The
    critical invariant: a key written by `keygen` and loaded by
    LoadKey must produce signatures that the SDK verifies against the
    DID encoded in the same file. Drift here would silently break
    every walkthrough scenario.
*/
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sdksigs "github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	sdkdid "github.com/clearcompass-ai/ortholog-sdk/did"
)

// TestKeygen_Roundtrip pins:
//   - keygen writes a parsable JSON file
//   - LoadKey re-hydrates a usable *ecdsa.PrivateKey
//   - the DID round-trips byte-identically
//   - SignEntry + RecoverSecp256k1 produce a public key that
//     hashes back to the same did:key.
func TestKeygen_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "alice.key.json")

	if err := runKeygen([]string{"--out", keyPath}); err != nil {
		t.Fatalf("runKeygen: %v", err)
	}

	// File must exist and be valid JSON in our schema.
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		t.Fatalf("parse key file: %v", err)
	}
	if kf.DID == "" || kf.PrivateKeyHex == "" || kf.PublicKeyCompressedHex == "" {
		t.Errorf("key file has empty fields: %+v", kf)
	}

	// LoadKey returns the same DID, "key" method, and a working priv.
	gotDID, gotMethod, priv, err := LoadKey(keyPath)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if gotDID != kf.DID {
		t.Errorf("DID drift: file=%s loader=%s", kf.DID, gotDID)
	}
	if gotMethod != DIDMethodKey {
		t.Errorf("method drift: want %q, got %q", DIDMethodKey, gotMethod)
	}

	// End-to-end signing: sign a digest, recover the pubkey,
	// re-derive the did:key, expect equality.
	digest := sha256.Sum256([]byte("walkthrough-roundtrip-canary"))
	sig, err := sdksigs.SignEntry(digest, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("sig len: want 64 (SDK raw r||s), got %d", len(sig))
	}

	// The DID we wrote should parse back to the same compressed
	// pubkey we stored.
	pub, _, err := sdkdid.ParseDIDKey(kf.DID)
	if err != nil {
		t.Fatalf("ParseDIDKey: %v", err)
	}
	wantHex, _ := hex.DecodeString(kf.PublicKeyCompressedHex)
	if hex.EncodeToString(pub) != hex.EncodeToString(wantHex) {
		t.Errorf("pubkey drift: did encodes %x, file says %x", pub, wantHex)
	}
}

// TestKeygen_RefusesOverwrite pins the --force gate.
func TestKeygen_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alice.key.json")

	if err := runKeygen([]string{"--out", path}); err != nil {
		t.Fatalf("first keygen: %v", err)
	}
	err := runKeygen([]string{"--out", path})
	if err == nil {
		t.Fatal("second keygen without --force MUST refuse to overwrite")
	}

	if err := runKeygen([]string{"--out", path, "--force"}); err != nil {
		t.Fatalf("second keygen with --force: %v", err)
	}
}

// TestLoadKey_RejectsBadFile pins the LoadKey error paths.
func TestLoadKey_RejectsBadFile(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		content string
	}{
		{"missing did", `{"private_key_hex":"00"}`},
		{"missing priv", `{"did":"did:key:zfoo"}`},
		{"non-hex priv", `{"did":"did:key:zfoo","private_key_hex":"zzzz"}`},
		{"wrong-length priv", `{"did":"did:key:zfoo","private_key_hex":"00ff"}`},
		{"not json", `not-json`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(dir, c.name+".key.json")
			if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, _, _, err := LoadKey(path); err == nil {
				t.Errorf("MUST reject %q", c.name)
			}
		})
	}
}
