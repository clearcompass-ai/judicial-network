/*
FILE PATH: cmd/network-api/davidson_scw_e2e_test.go

DESCRIPTION:
    Binary-level Davidson SCW end-to-end test.

    Distinct from tests/contracts/davidson_scw_e2e_test.go (which
    drives api.NewServer directly via httptest), this test boots
    cmd/network-api.run() as a real HTTP listener — every layer of
    the binary boot path is exercised:

      loadConfig → registerProductionBundles → buildKeyStore →
      buildAuthenticator → buildNonceStores (per-destination map) →
      buildJudicialDeps → api.NewServer → http.ListenAndServe.

    The flow itself mirrors the composer-level test:
      1. Stub operator (httptest.Server returning 202 SCT) is wired
         as OperatorEndpoint.
      2. Stub authenticator (injectingAuth) injects a fixed SCW DID
         into request context — stands in for production mTLS / JWT.
      3. Test POSTs to http://<binary-addr>/v1/judicial/cases.
      4. BuildResponse signing_payload is verified to match an
         independent envelope rebuild (drift detector).
      5. Test SHA-256 hashes the payload, signs via Phase 8b
         signer.Adapter, packs MinimalSCW, runs through the SDK
         verifier registry with stub eth_call.
      6. SIGINT triggers graceful shutdown; test confirms run()
         exits cleanly.

    Helpers (stub operator, fixtures, injecting auth) live in
    davidson_scw_e2e_setup_test.go.
*/
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"

	"github.com/clearcompass-ai/judicial-network/api/config"
	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
	keysigner "github.com/clearcompass-ai/judicial-network/api/exchange/keystore/signer"
	"github.com/clearcompass-ai/judicial-network/api/middleware"

	tndavidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
)

func TestBinaryE2E_DavidsonSCW_HappyPath(t *testing.T) {
	// 1. Stub operator + free port for the binary.
	op := stubOperator(t)
	defer op.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	// 2. Pre-allocate the keystore so the test can wire a Phase 8b
	// signer.Adapter against the same keystore the binary holds.
	ks := keystore.NewMemoryKeyStore()
	if _, err := ks.GenerateSecp256k1(binE2EOwnerDID, "signing"); err != nil {
		t.Fatalf("GenerateSecp256k1: %v", err)
	}
	signerAdapter, err := keysigner.New(ks, binE2EOwnerDID)
	if err != nil {
		t.Fatalf("signer.New: %v", err)
	}

	// 3. Operational config — JWT mode satisfies validate(); the
	// stub authenticator below replaces JWT semantics for the test.
	cfgPath := writeJSON(t, map[string]any{
		"listen_addr":             addr,
		"operator_endpoint":       op.URL,
		"artifact_store_endpoint": "http://art.test",
		"verification_endpoint":   "http://verify.test",
		"eth_rpc_endpoint":        "http://rpc.test",
		"keystore":                map[string]any{"backend": "memory"},
		"nonce_store": map[string]any{
			"backend":          "memory",
			"freshness_window": int64(time.Minute),
		},
		"auth": map[string]any{
			"mode":       "jwt",
			"jwt_issuer": "https://idp.test",
			"jwks_url":   "https://idp.test/.well-known/jwks.json",
		},
	})
	clearAPIEnv(t)

	// 4. Stub deps: pre-allocated keystore + injecting authenticator
	// that always sets the SCW DID as caller.
	scwDID := binE2EScwDID()
	stubDeps := deps{
		registerBundles: registerProductionBundles,
		newKeyStore: func(_ config.KeyStoreConfig) (keystore.KeyStore, error) {
			return ks, nil
		},
		newAuthenticator: func(_ config.AuthConfig) (middleware.Authenticator, error) {
			return injectingAuth{did: scwDID}, nil
		},
	}

	// 5. Boot the binary in a goroutine.
	runErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runErr <- run([]string{"--config", cfgPath}, stubDeps)
	}()

	// 6. Wait for /healthz.
	healthzURL := "http://" + addr + "/healthz"
	if !waitFor(t, 3*time.Second, func() bool {
		resp, err := http.Get(healthzURL)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}) {
		t.Fatalf("healthz never came up within 3s")
	}

	// 7. Drive POST /v1/judicial/cases over real HTTP.
	caseBody := []byte(`{
		"destination":   "` + tndavidson.ExchangeDID + `",
		"docket_number": "` + binE2EDocket + `",
		"case_type":     "criminal",
		"filed_date":    "2026-02-01",
		"event_time":    1761000000000000
	}`)
	resp, err := http.Post(
		"http://"+addr+"/v1/judicial/cases",
		"application/json",
		bytes.NewReader(caseBody),
	)
	if err != nil {
		t.Fatalf("POST /v1/judicial/cases: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, respBody)
	}

	// 8. Decode + drift-detect against an independent rebuild.
	var br struct {
		SigningPayload string                 `json:"signing_payload"`
		Header         envelope.ControlHeader `json:"header"`
	}
	if err := json.Unmarshal(respBody, &br); err != nil {
		t.Fatalf("decode BuildResponse: %v", err)
	}
	signingPayload, _ := base64.StdEncoding.DecodeString(br.SigningPayload)
	rebuilt := binE2ERebuild(t, scwDID, binE2EDocket, 1761000000000000)
	if want := envelope.SigningPayload(rebuilt); !bytes.Equal(want, signingPayload) {
		t.Fatalf("API signing_payload diverges from independent rebuild")
	}
	if br.Header.SignerDID != scwDID {
		t.Errorf("Header.SignerDID = %q, want %q", br.Header.SignerDID, scwDID)
	}

	// 9. SCW-sign + pack + verify — exact same shape as the composer
	// e2e but the bytes here came over real HTTP from the binary.
	digest := sha256.Sum256(signingPayload)
	ownerSig, err := signerAdapter.Sign(digest)
	if err != nil {
		t.Fatalf("signerAdapter.Sign: %v", err)
	}
	contractSig, err := signatures.PackMinimalSCWSignature(ownerSig)
	if err != nil {
		t.Fatalf("PackMinimalSCWSignature: %v", err)
	}
	rebuilt.Signatures = append(rebuilt.Signatures, envelope.Signature{
		SignerDID: scwDID, AlgoID: envelope.SigAlgoEIP1271, Bytes: contractSig,
	})
	if err := rebuilt.Validate(); err != nil {
		t.Fatalf("entry.Validate: %v", err)
	}
	rpc := signatures.NewStubEthereumRPC()
	calldata := signatures.EncodeIsValidSignatureCalldata(digest, contractSig)
	rpc.BindEthCall(binE2EAddr(), calldata, binE2EMagicReturn())
	registry := did.DefaultVerifierRegistryWithRPC(tndavidson.ExchangeDID, panicResolver{}, rpc)
	if err := registry.VerifyEntry(rebuilt); err != nil {
		t.Fatalf("verifier registry rejected binary-built entry: %v", err)
	}

	// 10. Graceful shutdown.
	proc, _ := os.FindProcess(os.Getpid())
	if err := proc.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal: %v", err)
	}
	select {
	case err := <-runErr:
		if err != nil {
			t.Errorf("run exited with %v; want nil after graceful shutdown", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not exit within 3s of signal")
	}
	wg.Wait()
}
