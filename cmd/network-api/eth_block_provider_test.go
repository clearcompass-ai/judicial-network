package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/did"
)

// rpcStub is a minimal Ethereum JSON-RPC server for BlockProvider
// tests. It answers eth_blockNumber with head and eth_getBlockByNumber
// with a deterministic hash derived from the requested height.
type rpcStub struct {
	head      uint64
	failBlock bool // when true, eth_getBlockByNumber returns result:null
}

func (s *rpcStub) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "eth_blockNumber":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":"0x%x"}`, s.head)
		case "eth_getBlockByNumber":
			if s.failBlock {
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":null}`)
				return
			}
			tag, _ := req.Params[0].(string)
			// Echo the requested number; hash = 0xAB repeated for the
			// low byte set to a function of the tag length (deterministic).
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"number":%q,"hash":"0x%064x"}}`, tag, 0xABCD)
		default:
			http.Error(w, "unexpected method", http.StatusBadRequest)
		}
	}
}

func TestEthBlockProvider_Pin_SubtractsConfirmationDepth(t *testing.T) {
	stub := &rpcStub{head: 1000}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	// allowInsecureHTTP=true because httptest serves http://.
	bp, err := newEthBlockProvider(srv.URL, 12, time.Second, true)
	if err != nil {
		t.Fatalf("newEthBlockProvider: %v", err)
	}
	num, hash, err := bp.Pin(context.Background())
	if err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if num != 988 { // 1000 - 12
		t.Errorf("pinned block = %d, want 988", num)
	}
	if hash == ([32]byte{}) {
		t.Error("pinned hash must be non-zero")
	}
}

func TestEthBlockProvider_Pin_ShallowHead(t *testing.T) {
	stub := &rpcStub{head: 5}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	bp, err := newEthBlockProvider(srv.URL, 12, time.Second, true)
	if err != nil {
		t.Fatalf("newEthBlockProvider: %v", err)
	}
	_, _, err = bp.Pin(context.Background())
	if !errors.Is(err, did.ErrBlockProviderUnavailable) {
		t.Fatalf("shallow head MUST surface ErrBlockProviderUnavailable; got %v", err)
	}
}

func TestEthBlockProvider_Pin_BlockNotFound(t *testing.T) {
	stub := &rpcStub{head: 1000, failBlock: true}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	bp, err := newEthBlockProvider(srv.URL, 12, time.Second, true)
	if err != nil {
		t.Fatalf("newEthBlockProvider: %v", err)
	}
	_, _, err = bp.Pin(context.Background())
	if !errors.Is(err, did.ErrBlockProviderUnavailable) {
		t.Fatalf("missing block MUST surface ErrBlockProviderUnavailable; got %v", err)
	}
}

func TestEthBlockProvider_RejectsInsecureHTTPWithoutOptIn(t *testing.T) {
	_, err := newEthBlockProvider("http://localhost:8545", 12, time.Second, false)
	if err == nil {
		t.Fatal("http:// endpoint MUST be rejected without allowInsecureHTTP")
	}
}

func TestEthBlockProvider_SatisfiesSDKInterface(t *testing.T) {
	// Compile-time pin: a rename of did.BlockProvider breaks the build.
	var _ did.BlockProvider = (*ethBlockProvider)(nil)
}
