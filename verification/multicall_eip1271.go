/*
FILE PATH: verification/multicall_eip1271.go

DESCRIPTION:

	JN adapter for attesta v0.8.2+'s crypto/multicall3 package. Batches
	N EIP-1271 isValidSignature verifications into a SINGLE eth_call
	against the canonical Multicall3 contract address (deployed at the
	same CREATE2 address on every production EVM chain:
	0xcA11bde05977b3631167028862bE2a173976CA11).

	Without batching, an admission flow that accepts M entries signed
	by smart-contract wallets issues M eth_call round trips at the
	Ethereum RPC node — commodity providers begin returning HTTP 429
	well before 500 req/min sustained. The aggregate3 entry-point
	turns that into ONE round trip, regardless of M.

ALGORITHM:

	  1. Caller assembles []multicall3.EIP1271Check — one tuple per
	     (wallet address, digest the wallet must approve, contract
	     signature bytes). The digest is SHA-256 of the SDK-canonical
	     entry signing payload — NOT a keccak256 over some message.
	  2. multicall3.BuildEIP1271Calls converts the checks to []Call3
	     with AllowFailure=true (so one reverting wallet doesn't sink
	     the rest of the batch).
	  3. multicall3.PackAggregate3 ABI-encodes the Call3 slice into
	     the calldata bytes for aggregate3((address,bool,bytes)[]).
	  4. The configured signatures.EthereumRPCClient issues a single
	     EthCall to multicall3CanonicalAddress at the given blockTag.
	  5. multicall3.UnpackAggregate3Results parses the returnData into
	     []multicall3.Result with strict ABI bounds checks.
	  6. multicall3.ParseEIP1271Results pairs each Result with its
	     source EIP1271Check and produces one EIP1271Verdict per check
	     (Magic=true iff the canonical 0x1626ba7e magic prefix appears
	     with all-zero high bits; otherwise Err is populated with the
	     SDK's typed sentinel).

KEY ARCHITECTURAL DECISIONS:

  - This file owns ONLY the orchestration. The byte-exact ABI
    pack/unpack lives in attesta/crypto/multicall3 and is never
    duplicated here. A future ABI fix lands in the SDK, not here.

  - AllowFailure=true is the SDK default for EIP-1271 batches. A
    revert in wallet K does not invalidate verdicts for wallets
    0..K-1, K+1..N-1 — the per-check verdict carries Err.

  - Empty checks short-circuits to (nil, nil) WITHOUT issuing any
    RPC. Callers do not need to special-case N=0.

  - Block-tag pinning is the caller's responsibility. The wrapper
    defaults to "latest" only when blockTag == ""; production
    admission flows pin to a specific block number per batch to
    keep verdicts deterministic across replays.

  - Stateless. No locks, no caches. Layered batch caches (the
    SDK's did.EIP1271BatchCache) compose on top of this; this
    file is the round-trip primitive.

TRUST ALIGNMENT:

	Implements Ledger Principle 5 (the "Melt-Proof" Mandate —
	respecting EVM RPC socket physics by amortising N calls into 1)
	and SDK Principle 3 (Fail-Closed Cryptographic APIs — every
	rejection path returns a typed error reachable via errors.Is,
	so callers cannot accidentally treat a malformed return as
	"verified").

KEY DEPENDENCIES:
  - attesta/crypto/multicall3: ABI pack/unpack primitives + the
    EIP-1271 verdict helpers (v0.8.2+).
  - attesta/crypto/signatures: EthereumRPCClient transport contract
    + ErrEthCallReverted sentinel.
*/
package verification

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/clearcompass-ai/attesta/crypto/multicall3"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
)

// ErrBatchEIP1271 wraps every error path the batch verifier
// surfaces. SDK sentinels remain reachable via errors.Is —
// e.g., errors.Is(err, signatures.ErrEthCallReverted),
// errors.Is(err, multicall3.ErrEIP1271BadMagic),
// errors.Is(err, multicall3.ErrEIP1271ReturnTooShort).
var ErrBatchEIP1271 = errors.New("verification/multicall_eip1271")

// multicall3CanonicalAddress is the [20]byte form of
// multicall3.Multicall3CanonicalAddressHex, decoded once at
// package-init time so every batch call is allocation-free on
// the address path.
var multicall3CanonicalAddress [signatures.EthereumAddressLen]byte

func init() {
	raw, err := decodeHex20(multicall3.Multicall3CanonicalAddressHex)
	if err != nil {
		// SDK constant — drift here is a programming error in the
		// SDK, not a runtime condition the JN handler can recover
		// from. Surface loudly at process start.
		panic(fmt.Sprintf("verification: malformed multicall3.Multicall3CanonicalAddressHex %q: %v",
			multicall3.Multicall3CanonicalAddressHex, err))
	}
	multicall3CanonicalAddress = raw
}

// decodeHex20 parses a "0x"-prefixed (or bare) 20-byte hex string
// into a fixed-size array. Returns an error if the decoded length
// is not exactly 20 bytes.
func decodeHex20(s string) ([signatures.EthereumAddressLen]byte, error) {
	var out [signatures.EthereumAddressLen]byte
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(raw) != signatures.EthereumAddressLen {
		return out, fmt.Errorf("want %d bytes, got %d", signatures.EthereumAddressLen, len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// Multicall3Address returns the canonical Multicall3 deployment
// address (0xcA11bde05977b3631167028862bE2a173976CA11) as a
// [20]byte. Exported so callers can pin the address in tests or
// in audit traces without re-decoding the hex constant.
func Multicall3Address() [signatures.EthereumAddressLen]byte {
	return multicall3CanonicalAddress
}

// VerifyBatchEIP1271 batches N EIP-1271 verifications into a
// SINGLE aggregate3 eth_call against the canonical Multicall3
// contract address, then returns one verdict per input check in
// the SAME order as `checks`.
//
// Returns (nil, nil) for an empty `checks` slice WITHOUT issuing
// any RPC. blockTag defaults to "latest" when empty; production
// admission flows should pin to a specific block number per
// batch for deterministic replays.
//
// Errors:
//
//   - nil rpc: ErrBatchEIP1271 wrapping a descriptive message.
//   - aggregate3 itself reverts at the EVM (e.g., Multicall3 not
//     deployed at the target address on this chain): ErrBatchEIP1271
//     wrapping signatures.ErrEthCallReverted (reachable via
//     errors.Is).
//   - aggregate3 returns malformed bytes: ErrBatchEIP1271 wrapping
//     the multicall3 decoder's typed error.
//   - aggregate3 length mismatch: ErrBatchEIP1271 wrapping
//     multicall3.ErrEIP1271CallLenMismatch.
//
// Per-check failures (one wallet reverted, returned non-magic,
// returned a short payload) populate Verdict.Err on the
// individual verdict; they are NOT returned as the top-level
// error. A partially-bad batch still surfaces its good verdicts.
func VerifyBatchEIP1271(
	ctx context.Context,
	rpc signatures.EthereumRPCClient,
	checks []multicall3.EIP1271Check,
	blockTag string,
) ([]multicall3.EIP1271Verdict, error) {
	if rpc == nil {
		return nil, fmt.Errorf("%w: nil EthereumRPCClient", ErrBatchEIP1271)
	}
	if len(checks) == 0 {
		return nil, nil
	}
	if blockTag == "" {
		blockTag = "latest"
	}
	calls := multicall3.BuildEIP1271Calls(checks)
	calldata := multicall3.PackAggregate3(calls)
	returnData, err := rpc.EthCall(ctx, multicall3CanonicalAddress, calldata, blockTag)
	if err != nil {
		return nil, fmt.Errorf("%w: aggregate3 eth_call: %w", ErrBatchEIP1271, err)
	}
	results, err := multicall3.UnpackAggregate3Results(returnData)
	if err != nil {
		return nil, fmt.Errorf("%w: decode aggregate3 results: %w", ErrBatchEIP1271, err)
	}
	verdicts, err := multicall3.ParseEIP1271Results(checks, results)
	if err != nil {
		return nil, fmt.Errorf("%w: parse verdicts: %w", ErrBatchEIP1271, err)
	}
	return verdicts, nil
}
