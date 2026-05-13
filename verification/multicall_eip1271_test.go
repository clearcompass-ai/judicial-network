/*
FILE PATH: verification/multicall_eip1271_test.go

DESCRIPTION:

	Tests for the multicall3 EIP-1271 batch verifier wrapper.

	Coverage:
	  - Canonical address constant decodes to the deployed
	    CREATE2 address.
	  - Empty checks short-circuits to (nil, nil) without
	    issuing any RPC.
	  - Nil rpc returns ErrBatchEIP1271 without panicking.
	  - blockTag defaults to "latest" when empty.
	  - Calldata sent to EthCall matches what
	    multicall3.PackAggregate3 would produce — proves the
	    wrapper does NOT re-encode at the boundary.
	  - aggregate3 happy path: 2 wallets, both return magic →
	    both verdicts Magic=true.
	  - aggregate3 mixed: 1 wallet magic, 1 wallet non-magic →
	    per-check verdict (magic, ErrEIP1271BadMagic).
	  - aggregate3 short return: 1 wallet returns 4 bytes →
	    per-check Err = ErrEIP1271ReturnTooShort.
	  - aggregate3 revert at the EVM (whole eth_call reverts) →
	    top-level error wraps signatures.ErrEthCallReverted.
*/
package verification

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/clearcompass-ai/attesta/crypto/multicall3"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
)

// encodeAggregate3Results ABI-encodes a []multicall3.Result into
// the byte layout returned by Multicall3.aggregate3 on chain.
// Mirrors the unexported buildResultsPayload helper in
// attesta/crypto/multicall3/decode_test.go — the SDK does not
// export a result-packer, so JN's tests own this small encoder.
//
// Layout (per Solidity ABI for tuple[] dynamic-bytes element):
//
//	outer-offset       (32 bytes, value 0x20)
//	array length       (32 bytes, big-endian uint64 in low 8 bytes)
//	[per-element-offset (32 bytes)] x N
//	[per-element body] x N:
//	  Success bool      (32 bytes, value 0 or 1 in last byte)
//	  bytes offset      (32 bytes, value 0x40)
//	  bytes length      (32 bytes)
//	  bytes payload     (length bytes, padded to multiple of 32)
func encodeAggregate3Results(results []multicall3.Result) []byte {
	const wordSize = 32

	padTo32 := func(n int) int {
		if n%wordSize == 0 {
			return 0
		}
		return wordSize - (n % wordSize)
	}
	encodeWord64 := func(v uint64) []byte {
		out := make([]byte, wordSize)
		binary.BigEndian.PutUint64(out[24:], v)
		return out
	}
	encodeBoolWord := func(b bool) []byte {
		out := make([]byte, wordSize)
		if b {
			out[31] = 1
		}
		return out
	}

	headSize := wordSize * len(results)
	elementBodySizes := make([]int, len(results))
	totalTail := 0
	for i, r := range results {
		size := 3*wordSize + len(r.ReturnData) + padTo32(len(r.ReturnData))
		elementBodySizes[i] = size
		totalTail += size
	}

	out := make([]byte, 0, 2*wordSize+headSize+totalTail)
	out = append(out, encodeWord64(wordSize)...)
	out = append(out, encodeWord64(uint64(len(results)))...)

	cursor := headSize
	for _, sz := range elementBodySizes {
		out = append(out, encodeWord64(uint64(cursor))...)
		cursor += sz
	}

	for _, r := range results {
		out = append(out, encodeBoolWord(r.Success)...)
		out = append(out, encodeWord64(2*wordSize)...)
		out = append(out, encodeWord64(uint64(len(r.ReturnData)))...)
		out = append(out, r.ReturnData...)
		if pad := padTo32(len(r.ReturnData)); pad > 0 {
			out = append(out, make([]byte, pad)...)
		}
	}
	return out
}

// magicReturn is the canonical EIP-1271 success returnData:
// 0x1626ba7e followed by 28 zero bytes.
func magicReturn() []byte {
	out := make([]byte, 32)
	out[0], out[1], out[2], out[3] = 0x16, 0x26, 0xba, 0x7e
	return out
}

// badMagicReturn is the canonical EIP-1271 magic prefix with
// non-zero high bits — must be rejected.
func badMagicReturn() []byte {
	out := magicReturn()
	out[31] = 0xFF
	return out
}

// sampleAddr returns a deterministic 20-byte address for tests.
func sampleAddr(seed byte) [signatures.EthereumAddressLen]byte {
	var a [signatures.EthereumAddressLen]byte
	for i := range a {
		a[i] = seed + byte(i)
	}
	return a
}

// ─── canonical-address pin ─────────────────────────────

func TestMulticall3Address_DecodesToCanonicalDeployment(t *testing.T) {
	got := Multicall3Address()
	want, err := hex.DecodeString("cA11bde05977b3631167028862bE2a173976CA11")
	if err != nil {
		t.Fatalf("decode want: %v", err)
	}
	if !bytesEq(got[:], want) {
		t.Errorf("Multicall3Address() = %x, want %x", got[:], want)
	}
	// Also pin the SDK's hex constant — drift would break every
	// JN-side production deploy targeting an EVM mainnet.
	if !strings.EqualFold(
		strings.TrimPrefix(multicall3.Multicall3CanonicalAddressHex, "0x"),
		"cA11bde05977b3631167028862bE2a173976CA11",
	) {
		t.Errorf("multicall3.Multicall3CanonicalAddressHex drift: %q",
			multicall3.Multicall3CanonicalAddressHex)
	}
}

// ─── degenerate inputs ──────────────────────────────────

func TestVerifyBatchEIP1271_EmptyChecks_NoRPC(t *testing.T) {
	rpc := signatures.NewStubEthereumRPC()
	verdicts, err := VerifyBatchEIP1271(context.Background(), rpc, nil, "latest")
	if err != nil {
		t.Fatalf("empty checks MUST NOT error: %v", err)
	}
	if len(verdicts) != 0 {
		t.Errorf("empty checks MUST return empty verdicts; got len=%d", len(verdicts))
	}
	if got := rpc.CallCount("eth_call"); got != 0 {
		t.Errorf("empty checks MUST NOT issue any eth_call; got %d", got)
	}
}

func TestVerifyBatchEIP1271_NilRPC_ReturnsTypedError(t *testing.T) {
	_, err := VerifyBatchEIP1271(context.Background(), nil,
		[]multicall3.EIP1271Check{{Address: sampleAddr(0x10)}}, "latest")
	if !errors.Is(err, ErrBatchEIP1271) {
		t.Fatalf("nil rpc MUST surface ErrBatchEIP1271; got %v", err)
	}
}

// ─── calldata round-trip ───────────────────────────────

func TestVerifyBatchEIP1271_CalldataMatchesPackAggregate3(t *testing.T) {
	rpc := signatures.NewStubEthereumRPC()

	checks := []multicall3.EIP1271Check{
		{Address: sampleAddr(0x10), Hash: [32]byte{0xAA}, Signature: []byte("sig-a")},
		{Address: sampleAddr(0x20), Hash: [32]byte{0xBB}, Signature: []byte("sig-b")},
	}
	wantCalldata := multicall3.PackAggregate3(multicall3.BuildEIP1271Calls(checks))
	rpc.BindEthCall(Multicall3Address(), wantCalldata,
		encodeAggregate3Results([]multicall3.Result{
			{Success: true, ReturnData: magicReturn()},
			{Success: true, ReturnData: magicReturn()},
		}))

	_, err := VerifyBatchEIP1271(context.Background(), rpc, checks, "latest")
	if err != nil {
		t.Fatalf("VerifyBatchEIP1271 with bound calldata MUST succeed; got %v", err)
	}
	if got := rpc.CallCount("eth_call"); got != 1 {
		t.Errorf("expected exactly 1 eth_call for the batch; got %d", got)
	}
}

func TestVerifyBatchEIP1271_DefaultsBlockTagToLatest(t *testing.T) {
	rpc := signatures.NewStubEthereumRPC()
	checks := []multicall3.EIP1271Check{
		{Address: sampleAddr(0x30), Hash: [32]byte{0xCC}, Signature: []byte("s")},
	}
	calldata := multicall3.PackAggregate3(multicall3.BuildEIP1271Calls(checks))
	rpc.BindEthCall(Multicall3Address(), calldata,
		encodeAggregate3Results([]multicall3.Result{
			{Success: true, ReturnData: magicReturn()},
		}))

	if _, err := VerifyBatchEIP1271(context.Background(), rpc, checks, ""); err != nil {
		t.Fatalf("VerifyBatchEIP1271 with empty blockTag: %v", err)
	}
	if got := rpc.LastBlockTag(); got != "latest" {
		t.Errorf("empty blockTag MUST default to \"latest\"; got %q", got)
	}
}

// ─── happy + mixed verdicts ──────────────────────────────

func TestVerifyBatchEIP1271_HappyPath_BothMagic(t *testing.T) {
	rpc := signatures.NewStubEthereumRPC()
	checks := []multicall3.EIP1271Check{
		{Address: sampleAddr(0x40), Hash: [32]byte{0xD1}, Signature: []byte("s1")},
		{Address: sampleAddr(0x50), Hash: [32]byte{0xD2}, Signature: []byte("s2")},
	}
	calldata := multicall3.PackAggregate3(multicall3.BuildEIP1271Calls(checks))
	rpc.BindEthCall(Multicall3Address(), calldata,
		encodeAggregate3Results([]multicall3.Result{
			{Success: true, ReturnData: magicReturn()},
			{Success: true, ReturnData: magicReturn()},
		}))

	verdicts, err := VerifyBatchEIP1271(context.Background(), rpc, checks, "latest")
	if err != nil {
		t.Fatalf("VerifyBatchEIP1271: %v", err)
	}
	if len(verdicts) != 2 {
		t.Fatalf("len(verdicts) = %d, want 2", len(verdicts))
	}
	for i, v := range verdicts {
		if !v.Magic {
			t.Errorf("verdict[%d].Magic = false; want true (err=%v)", i, v.Err)
		}
		if v.Err != nil {
			t.Errorf("verdict[%d].Err = %v; want nil", i, v.Err)
		}
		if v.Address != checks[i].Address {
			t.Errorf("verdict[%d].Address = %x; want %x",
				i, v.Address[:], checks[i].Address[:])
		}
	}
}

func TestVerifyBatchEIP1271_MixedBadMagic_PerCheckErr(t *testing.T) {
	rpc := signatures.NewStubEthereumRPC()
	checks := []multicall3.EIP1271Check{
		{Address: sampleAddr(0x60), Hash: [32]byte{0xE1}, Signature: []byte("ok")},
		{Address: sampleAddr(0x70), Hash: [32]byte{0xE2}, Signature: []byte("bad")},
	}
	calldata := multicall3.PackAggregate3(multicall3.BuildEIP1271Calls(checks))
	rpc.BindEthCall(Multicall3Address(), calldata,
		encodeAggregate3Results([]multicall3.Result{
			{Success: true, ReturnData: magicReturn()},
			{Success: true, ReturnData: badMagicReturn()},
		}))

	verdicts, err := VerifyBatchEIP1271(context.Background(), rpc, checks, "latest")
	if err != nil {
		t.Fatalf("VerifyBatchEIP1271: %v", err)
	}
	if !verdicts[0].Magic {
		t.Errorf("verdict[0] should be magic")
	}
	if verdicts[1].Magic {
		t.Errorf("verdict[1] should NOT be magic")
	}
	if !errors.Is(verdicts[1].Err, multicall3.ErrEIP1271BadMagic) {
		t.Errorf("verdict[1].Err = %v; want ErrEIP1271BadMagic", verdicts[1].Err)
	}
}

func TestVerifyBatchEIP1271_PartialRevert_PerCheckErr(t *testing.T) {
	rpc := signatures.NewStubEthereumRPC()
	checks := []multicall3.EIP1271Check{
		{Address: sampleAddr(0x80), Hash: [32]byte{0xF1}, Signature: []byte("ok")},
		{Address: sampleAddr(0x90), Hash: [32]byte{0xF2}, Signature: []byte("revert")},
	}
	calldata := multicall3.PackAggregate3(multicall3.BuildEIP1271Calls(checks))
	// aggregate3 with AllowFailure=true reports the revert as
	// Result.Success=false with empty ReturnData.
	rpc.BindEthCall(Multicall3Address(), calldata,
		encodeAggregate3Results([]multicall3.Result{
			{Success: true, ReturnData: magicReturn()},
			{Success: false, ReturnData: nil},
		}))

	verdicts, err := VerifyBatchEIP1271(context.Background(), rpc, checks, "latest")
	if err != nil {
		t.Fatalf("VerifyBatchEIP1271: %v", err)
	}
	if !verdicts[0].Magic {
		t.Errorf("verdict[0] should be magic")
	}
	if verdicts[1].Magic {
		t.Errorf("verdict[1] should NOT be magic (call reverted)")
	}
	if verdicts[1].Err == nil {
		t.Errorf("verdict[1].Err must be non-nil for reverted call")
	}
}

func TestVerifyBatchEIP1271_ShortReturn_PerCheckErr(t *testing.T) {
	rpc := signatures.NewStubEthereumRPC()
	checks := []multicall3.EIP1271Check{
		{Address: sampleAddr(0xA0), Hash: [32]byte{0xAB}, Signature: []byte("short")},
	}
	calldata := multicall3.PackAggregate3(multicall3.BuildEIP1271Calls(checks))
	rpc.BindEthCall(Multicall3Address(), calldata,
		encodeAggregate3Results([]multicall3.Result{
			{Success: true, ReturnData: []byte{0x16, 0x26, 0xba, 0x7e}},
		}))

	verdicts, err := VerifyBatchEIP1271(context.Background(), rpc, checks, "latest")
	if err != nil {
		t.Fatalf("VerifyBatchEIP1271: %v", err)
	}
	if verdicts[0].Magic {
		t.Errorf("verdict[0].Magic = true on 4-byte return; want false")
	}
	if !errors.Is(verdicts[0].Err, multicall3.ErrEIP1271ReturnTooShort) {
		t.Errorf("verdict[0].Err = %v; want ErrEIP1271ReturnTooShort", verdicts[0].Err)
	}
}

// ─── top-level RPC failures wrap SDK sentinels ─────────────────

func TestVerifyBatchEIP1271_AggregateRevert_WrapsSDKSentinel(t *testing.T) {
	rpc := signatures.NewStubEthereumRPC()
	checks := []multicall3.EIP1271Check{
		{Address: sampleAddr(0xB0), Hash: [32]byte{0xBA}, Signature: []byte("s")},
	}
	calldata := multicall3.PackAggregate3(multicall3.BuildEIP1271Calls(checks))
	rpc.BindEthCallError(Multicall3Address(), calldata, signatures.ErrEthCallReverted)

	_, err := VerifyBatchEIP1271(context.Background(), rpc, checks, "latest")
	if !errors.Is(err, ErrBatchEIP1271) {
		t.Errorf("aggregate3 revert MUST wrap ErrBatchEIP1271; got %v", err)
	}
	if !errors.Is(err, signatures.ErrEthCallReverted) {
		t.Errorf("aggregate3 revert MUST keep signatures.ErrEthCallReverted reachable via errors.Is; got %v", err)
	}
}

// ─── compile-time pins for the v0.8.2 multicall3 SDK seam ──────
//
// A rename or removal of any of these in the SDK breaks the JN
// build BEFORE any runtime test runs.
var (
	_ = multicall3.Multicall3CanonicalAddressHex
	_ = multicall3.AggregateSelector
	_ = multicall3.MaxResultsLength
	_ = multicall3.BuildEIP1271Calls
	_ = multicall3.PackAggregate3
	_ = multicall3.UnpackAggregate3Results
	_ = multicall3.ParseEIP1271Results
	_ = multicall3.ErrEIP1271BadMagic
	_ = multicall3.ErrEIP1271ReturnTooShort
	_ multicall3.Call3
	_ multicall3.Result
	_ multicall3.EIP1271Check
	_ multicall3.EIP1271Verdict
)

// ─── byte-equality helper ────────────────────────────────

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
