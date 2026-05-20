/*
FILE PATH: internal/testutil/multicall3.go

DESCRIPTION:

	Test-only helpers for EIP-1271 / smart-contract-wallet
	verification against the attesta v1.7.1 PKHVerifier, which fans
	every isValidSignature call through Multicall3.aggregate3 to a
	K-of-N executor quorum at the canonical Multicall3 deployer
	address.

	The SDK exports the aggregate3 *calldata* encoder
	(multicall3.PackAggregate3) and the *response* decoder
	(multicall3.UnpackAggregate3Results) but NOT a response encoder —
	the only one in the SDK is unexported test code. JN tests in more
	than one package (tests/contracts and cmd/network-api) need to
	program stub eth_call bindings with aggregate3 responses, so the
	encoder + canonical-address helpers live here, shared, rather than
	cloned per package.

	Lives under internal/ so it cannot escape the module, and is
	imported only from _test.go files so it never enters a production
	binary.

KEY DEPENDENCIES:
  - attesta/crypto/multicall3: Multicall3CanonicalAddressHex.
  - attesta/crypto/signatures: EthereumAddressLen.
*/
package testutil

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/clearcompass-ai/attesta/crypto/multicall3"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
)

// Multicall3Addr returns the canonical Multicall3 deployer address
// (0xcA11bde05977b3631167028862bE2a173976CA11). The v1.7.1
// PKHVerifier hits THIS address — not the wallet contract — on every
// EIP-1271 verification call, so stubs bind against it.
func Multicall3Addr() [signatures.EthereumAddressLen]byte {
	raw, err := hex.DecodeString(multicall3.Multicall3CanonicalAddressHex[2:]) // skip "0x"
	if err != nil || len(raw) != signatures.EthereumAddressLen {
		// The SDK constant is a compile-time-fixed 20-byte hex string;
		// a decode failure here means the SDK constant drifted, which
		// every SCW test would catch anyway.
		panic("testutil: malformed Multicall3CanonicalAddressHex")
	}
	var out [signatures.EthereumAddressLen]byte
	copy(out[:], raw)
	return out
}

// EncodeAggregate3Response builds the canonical bytes a Multicall3
// aggregate3 call returns for a single-check batch. success encodes
// the per-call success flag; returnData is the inner isValidSignature
// return (e.g., the EIP-1271 magic value or 32 zero bytes for a
// non-magic verdict).
//
// Layout (single check, dynamic-bytes inner return):
//
//	[0x00 .. 0x20)  offset to outer dynamic array (0x20)
//	[0x20 .. 0x40)  array length (1)
//	[0x40 .. 0x60)  offset to tuple element (0x20 from element start)
//	[0x60 .. 0x80)  bool success
//	[0x80 .. 0xA0)  offset to inner bytes (0x40)
//	[0xA0 .. 0xC0)  inner bytes length
//	[0xC0 ..    )   inner bytes padded to a 32-byte boundary
//
// Pinned against the SDK's own test encoder (attesta/tests
// /verify_entry_signatures_matrix_test.go::encodeAggregate3Response);
// a drift here is a Multicall3 wire-format change.
func EncodeAggregate3Response(success bool, returnData []byte) []byte {
	rdLen := len(returnData)
	pad := (32 - rdLen%32) % 32
	out := make([]byte, 0, 7*32+rdLen+pad)
	appendWord := func(v uint64) {
		var word [32]byte
		binary.BigEndian.PutUint64(word[24:32], v)
		out = append(out, word[:]...)
	}
	appendBool := func(b bool) {
		var word [32]byte
		if b {
			word[31] = 1
		}
		out = append(out, word[:]...)
	}
	appendWord(0x20)
	appendWord(1)
	appendWord(0x20)
	appendBool(success)
	appendWord(0x40)
	appendWord(uint64(rdLen))
	out = append(out, returnData...)
	out = append(out, make([]byte, pad)...)
	return out
}
