/*
FILE PATH: cmd/judicial-cli/keys.go

DESCRIPTION:

	`keygen` subcommand and the on-disk key-file format that every
	other subcommand reads. Mints two flavors of real DID:

	  --method key           (default)
	    did:key:zQ3sh… via sdkdid.GenerateDIDKeySecp256k1.
	    Same primitive the ledger's loadOrGenerateLedgerSigner
	    uses (cmd/ledger/main.go:189-200). Used by court personnel
	    whose identity isn't tied to an Ethereum wallet.

	  --method pkh-eip155 [--chain-id 1]
	    did:pkh:eip155:<chainId>:0x<addr> per CAIP-10.
	    20-byte Ethereum address derived as Keccak256(uncompressed
	    pubkey[1:])[12:]. Used by parties (plaintiffs, defendants,
	    outside witnesses) whose primary identity lives in an
	    Ethereum-compatible wallet (MetaMask, Coinbase Wallet,
	    Privy embedded wallet, etc.). Verifies through PKHVerifier.

	The key file's `did_method` field tells the submitter which
	signing path to use:
	  - did:key  -> SignEntry (64-byte r||s) + SigAlgoECDSA
	  - did:pkh  -> SignEthereumRecoverable (65-byte r||s||v) +
	                SigAlgoEIP191 (with EIP-191 prefix digest)

	Key file is plaintext JSON for walkthrough simplicity.
	Production consumers swap this layer for a signing service
	backed by an HSM or Privy's IdentityProvider — same shape over
	the wire either way.

KEY DEPENDENCIES:
  - sdkdid.GenerateDIDKeySecp256k1
  - sdksigs.AddressFromPubkey, PubKeyBytes
  - decred secp256k1 (PrivKeyFromBytes for re-hydration)
*/
package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	secp256k1ec "github.com/decred/dcrd/dcrec/secp256k1/v4"

	sdksigs "github.com/clearcompass-ai/attesta/crypto/signatures"
	sdkdid "github.com/clearcompass-ai/attesta/did"
)

// DID method names recognized by the CLI.
const (
	DIDMethodKey       = "key"        // did:key:zQ3sh...
	DIDMethodPKHEIP155 = "pkh-eip155" // did:pkh:eip155:<chainId>:0x<addr>
)

// KeyFile is the on-disk format for a judicial-cli-issued keypair.
// Compatible with both did:key and did:pkh — the `did_method` field
// disambiguates. Old key files (without did_method) parse cleanly
// and default to "key" for backwards compatibility.
type KeyFile struct {
	DID                    string `json:"did"`
	DIDMethod              string `json:"did_method,omitempty"`           // "key" or "pkh-eip155"
	ChainID                int64  `json:"chain_id,omitempty"`             // pkh-eip155 only
	EthereumAddressHex     string `json:"ethereum_address_hex,omitempty"` // pkh-eip155 only
	PrivateKeyHex          string `json:"private_key_hex"`
	PublicKeyCompressedHex string `json:"public_key_compressed_hex"`
}

// runKeygen handles:
//
//	judicial-cli keygen --out FILE [--method key|pkh-eip155]
//	                              [--chain-id N]  (pkh-eip155 only; default 1)
//	                              [--force]
func runKeygen(args []string) error {
	fs := flagSet("keygen")
	out := fs.String("out", "", "path to write the key file (required)")
	method := fs.String("method", DIDMethodKey,
		`did method: "key" (default) or "pkh-eip155"`)
	chainID := fs.Int64("chain-id", 1, "EVM chain id (pkh-eip155 only; 1 = Ethereum mainnet)")
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

	// Same secp256k1 primitive both methods. Only the DID encoding
	// differs.
	pair, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		return wireErr("GenerateDIDKeySecp256k1: %w", err)
	}
	privBytes := privKeyTo32(pair.PrivateKey)

	kf := KeyFile{
		PrivateKeyHex:          hex.EncodeToString(privBytes),
		PublicKeyCompressedHex: hex.EncodeToString(pair.PublicKeyCompressed),
	}

	switch *method {
	case DIDMethodKey:
		kf.DID = pair.DID
		kf.DIDMethod = DIDMethodKey
	case DIDMethodPKHEIP155:
		// did:pkh DID = did:pkh:eip155:<chainId>:0x<addr>
		// where addr = last 20 bytes of Keccak256(uncompressed[1:]).
		uncompressed := sdksigs.PubKeyBytes(&pair.PrivateKey.PublicKey)
		addr, err := sdksigs.AddressFromPubkey(uncompressed)
		if err != nil {
			return wireErr("AddressFromPubkey: %w", err)
		}
		addrHex := hex.EncodeToString(addr[:])
		kf.DID = fmt.Sprintf("did:pkh:eip155:%d:0x%s", *chainID, addrHex)
		kf.DIDMethod = DIDMethodPKHEIP155
		kf.ChainID = *chainID
		kf.EthereumAddressHex = "0x" + addrHex
	default:
		return argsErr("unknown --method %q (valid: %q, %q)",
			*method, DIDMethodKey, DIDMethodPKHEIP155)
	}

	body, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return wireErr("marshal key file: %w", err)
	}
	if err := os.WriteFile(*out, append(body, '\n'), 0o600); err != nil {
		return argsErr("write key file: %w", err)
	}

	fmt.Printf("did=%s\n", kf.DID)
	fmt.Printf("method=%s\n", kf.DIDMethod)
	fmt.Printf("file=%s\n", *out)
	return nil
}

// LoadKey reads a KeyFile from disk and re-hydrates an
// *ecdsa.PrivateKey suitable for SDK signing primitives. Returns
// (did, did_method, *ecdsa.PrivateKey). did_method is "" for
// legacy files that predate the field — callers should treat ""
// the same as "key".
func LoadKey(path string) (did, method string, priv *ecdsa.PrivateKey, err error) {
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		return "", "", nil, fmt.Errorf("read key file %q: %w", path, rerr)
	}
	var kf KeyFile
	if uerr := json.Unmarshal(data, &kf); uerr != nil {
		return "", "", nil, fmt.Errorf("parse key file %q: %w", path, uerr)
	}
	if kf.DID == "" {
		return "", "", nil, fmt.Errorf("key file %q missing did", path)
	}
	if kf.PrivateKeyHex == "" {
		return "", "", nil, fmt.Errorf("key file %q missing private_key_hex", path)
	}
	privBytes, derr := hex.DecodeString(kf.PrivateKeyHex)
	if derr != nil {
		return "", "", nil, fmt.Errorf("key file %q: bad private_key_hex: %w", path, derr)
	}
	if len(privBytes) != 32 {
		return "", "", nil, fmt.Errorf("key file %q: private_key_hex must be 32 bytes, got %d",
			path, len(privBytes))
	}
	priv = privFromBytes(privBytes)
	method = kf.DIDMethod
	if method == "" {
		method = DIDMethodKey // legacy default
	}
	return kf.DID, method, priv, nil
}

// privKeyTo32 serializes an *ecdsa.PrivateKey to 32 bytes,
// big-endian (left-padding shorter values with zeros).
func privKeyTo32(priv *ecdsa.PrivateKey) []byte {
	out := make([]byte, 32)
	d := priv.D.Bytes()
	copy(out[32-len(d):], d)
	return out
}

// privFromBytes reverses privKeyTo32 via the decred secp256k1
// helper, producing the same *ecdsa.PrivateKey shape
// signatures.GenerateKey returns.
func privFromBytes(b []byte) *ecdsa.PrivateKey {
	return secp256k1ec.PrivKeyFromBytes(b).ToECDSA()
}
