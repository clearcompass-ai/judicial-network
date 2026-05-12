/*
FILE PATH: cmd/network-api/davidson_scw_e2e_setup_test.go

DESCRIPTION:

	Fixtures + helpers for the binary-level Davidson SCW e2e. Owns:

	  - binE2EAddr / binE2EScwDID / binE2EMagicReturn — deterministic
	    SCW contract fixture (distinct from the composer-level
	    fixture in tests/contracts so the two tests can coexist
	    without verifier-registry aliasing).
	  - injectingAuth — test-only middleware.Authenticator that
	    injects a fixed callerDID into request context. Stands in
	    for production mTLS / JWT.
	  - stubLedger — httptest.Server returning 202 SCT for POST
	    /v1/entries; mirrors the ledger's wire shape without the
	    Postgres / Tessera infrastructure.
	  - binE2ERebuild — independent envelope rebuild used as the
	    signing-payload drift detector.
	  - panicResolver — refuses every did:web Resolve call so any
	    accidental network traffic crashes loud.
*/
package main

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/did"

	"github.com/clearcompass-ai/judicial-network/api/middleware"
	"github.com/clearcompass-ai/judicial-network/cases"

	tndavidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
)

const (
	binE2EOwnerDID = "did:web:state:tn:davidson:clerk-eoa"
	binE2EDocket   = "TN-DAV-2026-CR-77777"
)

// binE2EAddr is a deterministic MinimalSCW contract address. Distinct
// from tests/contracts/davidson_scw_e2e_*'s addr so the two tests'
// verifier registries don't alias.
func binE2EAddr() [signatures.EthereumAddressLen]byte {
	var a [signatures.EthereumAddressLen]byte
	for i := range a {
		a[i] = byte(0xE0 + i)
	}
	return a
}

func binE2EScwDID() string {
	addr := binE2EAddr()
	return "did:pkh:eip155:1:0x" + hex.EncodeToString(addr[:])
}

// binE2EMagicReturn is the canonical EIP-1271 magic value
// (0x1626ba7e) padded to 32 bytes.
func binE2EMagicReturn() []byte {
	out := make([]byte, 32)
	out[0], out[1], out[2], out[3] = 0x16, 0x26, 0xba, 0x7e
	return out
}

// injectingAuth is a test-only middleware.Authenticator that injects
// a fixed callerDID into every request's context. Stands in for
// production mTLS / JWT auth without TLS material.
type injectingAuth struct{ did string }

func (a injectingAuth) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := middleware.WithCallerDID(r.Context(), a.did)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// stubLedger returns an httptest.Server that accepts POST /v1/entries
// (octet-stream) and returns a synthetic SCT JSON. The body is
// consumed to mirror real ledger behaviour; the test asserts
// non-empty bytes arrived.
func stubLedger(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/entries":
			body, _ := io.ReadAll(r.Body)
			if len(body) == 0 {
				http.Error(w, "empty body", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"sequence":42,"hash":"deadbeef"}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

// binE2ERebuild produces the same *envelope.Entry the case-initiate
// handler would build for the inputs we POSTed. The e2e test
// asserts envelope.SigningPayload(rebuilt) matches the API's
// signing_payload byte-for-byte.
func binE2ERebuild(t *testing.T, signerDID, docket string, eventTime int64) *envelope.Entry {
	t.Helper()
	res, err := cases.InitiateCase(cases.InitiationConfig{
		Destination:  tndavidson.ExchangeDID,
		SignerDID:    signerDID,
		DocketNumber: docket,
		CaseType:     "criminal",
		FiledDate:    "2026-02-01",
		EventTime:    eventTime,
	})
	if err != nil {
		t.Fatalf("InitiateCase (rebuild): %v", err)
	}
	return res.Entry
}

// panicResolver refuses every did:web Resolve call. The binary e2e
// uses did:pkh exclusively; any did:web traffic is a regression that
// should crash loud rather than silently hit the network.
type panicResolver struct{}

func (panicResolver) Resolve(context.Context, string) (*did.DIDDocument, error) {
	panic("binary e2e: did:web resolution not expected")
}
