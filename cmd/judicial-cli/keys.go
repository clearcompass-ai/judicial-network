/*
FILE PATH: cmd/judicial-cli/keys.go

DESCRIPTION:
    `keygen` subcommand and the on-disk key-file format that every
    other subcommand reads. Generates a real did:key (secp256k1) using
    the SDK's GenerateDIDKeySecp256k1 — same primitive the operator's
    own loadOrGenerateOperatorSigner uses, so the DIDs that flow off
    judicial-cli are wire-format-identical to operator-issued ones.

    Key file is plaintext JSON for walkthrough simplicity. Production
    consumers swap this layer for a signing service backed by an HSM
    or by Privy's IdentityProvider.

WIRE-COMPATIBILITY NOTE:
    The DID is encoded via did.EncodeDIDKey(MulticodecSecp256k1, …),
    matching:
      - operator/cmd/operator/main.go:189-200 (operator's own DID)
      - operator/cmd/submit-stamp/main.go:84  (existing CLI fixture)
      - sdk/did/creation.go:101-119           (the canonical generator)
    A judicial-cli-issued DID resolves cleanly through
    did.NewKeyResolver().
*/
package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	secp256k1ec "github.com/decred/dcrd/dcrec/secp256k1/v4"

	sdkdid "github.com/clearcompass-ai/ortholog-sdk/did"
)

// KeyFile is the on-disk format for a judicial-cli-issued keypair.
// The hex fields are case-insensitive on read; we always write
// lowercase. The DID is the multibase-encoded compressed pubkey
// (did:key:z…), wire-identical to what GenerateDIDKeySecp256k1 emits.
type KeyFile struct {
	DID                    string `json:"did"`
	PrivateKeyHex          string `json:"private_key_hex"`
	PublicKeyCompressedHex string `json:"public_key_compressed_hex"`
}

// runKeygen handles `judicial-cli keygen --out alice.key.json [--label alice]`.
// The --label is optional and stored only in the JSON envelope; the
// DID does not include it (DIDs are derived purely from the public
// key per spec).
func runKeygen(args []string) error {
	fs := flagSet("keygen")
	out := fs.String("out", "", "path to write the key file (required)")
	force := fs.Bool("force", false, "overwrite if --out exists")
	if err := fs.Parse(args); err != nil {
		return argsErr("parsing flags: %w", err)
	}
	if *out == "" {
		return argsErr("--out is required (path to write key JSON)")
	}
	if _, err := os.Stat(*out); err == nil && !*force {
		return argsErr("%s already exists; pass --force to overwrite", *out)
	}

	// Generate via SDK — same primitive operator uses.
	pair, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		return wireErr("GenerateDIDKeySecp256k1: %w", err)
	}

	// ecdsa.PrivateKey.D is *big.Int. Convert to fixed-32-byte
	// big-endian per secp256k1 convention.
	privBytes := privKeyTo32(pair.PrivateKey)

	kf := KeyFile{
		DID:                    pair.DID,
		PrivateKeyHex:          hex.EncodeToString(privBytes),
		PublicKeyCompressedHex: hex.EncodeToString(pair.PublicKeyCompressed),
	}
	body, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return wireErr("marshal key file: %w", err)
	}
	if err := os.WriteFile(*out, append(body, '\n'), 0o600); err != nil {
		return argsErr("write key file: %w", err)
	}

	fmt.Printf("did=%s\n", pair.DID)
	fmt.Printf("file=%s\n", *out)
	return nil
}

// LoadKey reads a KeyFile from disk and re-hydrates an
// *ecdsa.PrivateKey suitable for SDK signing primitives. The DID
// inside the file is returned alongside.
func LoadKey(path string) (string, *ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read key file %q: %w", path, err)
	}
	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return "", nil, fmt.Errorf("parse key file %q: %w", path, err)
	}
	if kf.DID == "" {
		return "", nil, fmt.Errorf("key file %q missing did", path)
	}
	if kf.PrivateKeyHex == "" {
		return "", nil, fmt.Errorf("key file %q missing private_key_hex", path)
	}
	privBytes, err := hex.DecodeString(kf.PrivateKeyHex)
	if err != nil {
		return "", nil, fmt.Errorf("key file %q: bad private_key_hex: %w", path, err)
	}
	if len(privBytes) != 32 {
		return "", nil, fmt.Errorf("key file %q: private_key_hex must be 32 bytes, got %d",
			path, len(privBytes))
	}
	priv := privFromBytes(privBytes)
	return kf.DID, priv, nil
}

// privKeyTo32 serializes an *ecdsa.PrivateKey to 32 bytes,
// big-endian. secp256k1 D values fit in 32 bytes; we left-pad
// shorter values with zeros.
func privKeyTo32(priv *ecdsa.PrivateKey) []byte {
	out := make([]byte, 32)
	d := priv.D.Bytes()
	copy(out[32-len(d):], d)
	return out
}

// privFromBytes reverses privKeyTo32 via the decred secp256k1
// helper, which produces the same *ecdsa.PrivateKey shape
// signatures.GenerateKey returns (Curve = secp256k1.S256(), full
// public-key fields). Re-using the upstream helper keeps the on-
// disk format and the in-memory shape signature-compatible.
func privFromBytes(b []byte) *ecdsa.PrivateKey {
	return secp256k1ec.PrivKeyFromBytes(b).ToECDSA()
}
