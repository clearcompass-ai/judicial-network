/*
FILE PATH: cmd/network-api/eth_block_provider.go

DESCRIPTION:

	HTTP head-tracking BlockProvider for EIP-1271 smart-contract-
	wallet verification. attesta v1.7.1's PKHVerifier pins every
	EIP-1271 eth_call to a specific (BlockNumber, BlockHash) supplied
	by a did.BlockProvider; the SDK ships only StaticBlockProvider
	(tests / pinned-replay) and leaves the production head-tracking
	provider to the consumer because the block-query surface is
	deployment-specific.

	The SDK's EthereumRPCClient interface exposes only EthCall +
	EthGetCode — no block-fetch — so this provider carries its own
	minimal JSON-RPC client for eth_blockNumber + eth_getBlockByNumber.

	# REORG SAFETY

	Pin returns (head - ConfirmationDepth). A signature verified
	against a block ConfirmationDepth deep is overwhelmingly unlikely
	to be reorged out from under an in-flight batch; the returned
	BlockHash is the canonical pin so even if the height is reorged
	the verifier re-executes against the exact block it recorded.

	# FAIL-CLOSED

	Any RPC failure, a head shallower than ConfirmationDepth, or a
	malformed block response surfaces as a wrapped
	did.ErrBlockProviderUnavailable. The PKHVerifier translates that
	into a transient (retryable) verification failure — never an
	implicit accept.

KEY DEPENDENCIES:
  - attesta/did: BlockProvider interface + ErrBlockProviderUnavailable.
*/
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/clearcompass-ai/attesta/did"
)

// ethBlockProvider is a did.BlockProvider backed by an Ethereum
// JSON-RPC endpoint. Concurrent-safe: each Pin issues independent
// HTTP requests with no shared mutable state.
type ethBlockProvider struct {
	endpoint          string
	confirmationDepth uint64
	httpClient        *http.Client
}

// compile-time assertion: ethBlockProvider satisfies the SDK contract.
var _ did.BlockProvider = (*ethBlockProvider)(nil)

// newEthBlockProvider constructs a head-tracking BlockProvider.
// endpoint MUST be https:// unless allowInsecureHTTP is set (local-dev
// only). confirmationDepth is the number of blocks behind head to pin.
func newEthBlockProvider(endpoint string, confirmationDepth uint64, timeout time.Duration, allowInsecureHTTP bool) (*ethBlockProvider, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("eth_block_provider: endpoint required")
	}
	lower := strings.ToLower(endpoint)
	if strings.HasPrefix(lower, "http://") && !allowInsecureHTTP {
		return nil, fmt.Errorf("eth_block_provider: refusing http:// endpoint without allowInsecureHTTP (production MUST use https://)")
	}
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return nil, fmt.Errorf("eth_block_provider: endpoint must be http(s)://")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &ethBlockProvider{
		endpoint:          endpoint,
		confirmationDepth: confirmationDepth,
		httpClient:        &http.Client{Timeout: timeout},
	}, nil
}

// Pin implements did.BlockProvider. Fetches the chain head, subtracts
// the confirmation depth, and returns the (number, hash) of the
// resulting block.
func (p *ethBlockProvider) Pin(ctx context.Context) (uint64, [32]byte, error) {
	head, err := p.blockNumber(ctx)
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("%w: eth_blockNumber: %v", did.ErrBlockProviderUnavailable, err)
	}
	if head < p.confirmationDepth {
		return 0, [32]byte{}, fmt.Errorf("%w: chain head %d is shallower than confirmation depth %d",
			did.ErrBlockProviderUnavailable, head, p.confirmationDepth)
	}
	target := head - p.confirmationDepth
	num, hash, err := p.blockByNumber(ctx, target)
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("%w: eth_getBlockByNumber(%d): %v", did.ErrBlockProviderUnavailable, target, err)
	}
	if num != target {
		return 0, [32]byte{}, fmt.Errorf("%w: node returned block %d for requested %d", did.ErrBlockProviderUnavailable, num, target)
	}
	if hash == ([32]byte{}) {
		return 0, [32]byte{}, fmt.Errorf("%w: node returned zero block hash at %d", did.ErrBlockProviderUnavailable, target)
	}
	return num, hash, nil
}

// jsonRPCRequest is the JSON-RPC 2.0 request envelope.
type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

// jsonRPCError is the JSON-RPC 2.0 error object.
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// blockNumber calls eth_blockNumber and parses the hex head height.
func (p *ethBlockProvider) blockNumber(ctx context.Context) (uint64, error) {
	var resp struct {
		Result string        `json:"result"`
		Error  *jsonRPCError `json:"error"`
	}
	if err := p.call(ctx, "eth_blockNumber", []any{}, &resp); err != nil {
		return 0, err
	}
	if resp.Error != nil {
		return 0, fmt.Errorf("json-rpc error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	return parseHexUint64(resp.Result)
}

// blockByNumber calls eth_getBlockByNumber and parses (number, hash).
func (p *ethBlockProvider) blockByNumber(ctx context.Context, number uint64) (uint64, [32]byte, error) {
	tag := "0x" + strconv.FormatUint(number, 16)
	var resp struct {
		Result *struct {
			Number string `json:"number"`
			Hash   string `json:"hash"`
		} `json:"result"`
		Error *jsonRPCError `json:"error"`
	}
	if err := p.call(ctx, "eth_getBlockByNumber", []any{tag, false}, &resp); err != nil {
		return 0, [32]byte{}, err
	}
	if resp.Error != nil {
		return 0, [32]byte{}, fmt.Errorf("json-rpc error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	if resp.Result == nil {
		return 0, [32]byte{}, fmt.Errorf("block not found")
	}
	num, err := parseHexUint64(resp.Result.Number)
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("parse block number: %w", err)
	}
	hash, err := parseHex32(resp.Result.Hash)
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("parse block hash: %w", err)
	}
	return num, hash, nil
}

// call issues a single JSON-RPC POST and decodes the response into out.
func (p *ethBlockProvider) call(ctx context.Context, method string, params []any, out any) error {
	body, err := json.Marshal(jsonRPCRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	httpResp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status %d", httpResp.StatusCode)
	}
	if err := json.NewDecoder(httpResp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// parseHexUint64 decodes a "0x"-prefixed hex string to uint64.
func parseHexUint64(s string) (uint64, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if s == "" {
		return 0, fmt.Errorf("empty hex value")
	}
	return strconv.ParseUint(s, 16, 64)
}

// parseHex32 decodes a "0x"-prefixed 32-byte hex string.
func parseHex32(s string) ([32]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	raw, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, err
	}
	if len(raw) != 32 {
		return [32]byte{}, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return out, nil
}
