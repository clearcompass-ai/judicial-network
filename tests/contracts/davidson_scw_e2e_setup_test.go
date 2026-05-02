/*
FILE PATH: tests/contracts/davidson_scw_e2e_setup_test.go

DESCRIPTION:
    Test fixtures + harness for davidson_scw_e2e_test.go. Owns:

      - SCW destination + DID + canonical addr / magic-value helpers
      - scwE2EHarness: composed listener + signer.Adapter + SCW DID
      - rebuildUnsignedEntry: independent rebuild used as the
        signing-payload drift detector

    Kept in a sibling file so the main e2e test stays under the
    300-line cap and the harness can be shared by future SCW tests
    (cross-court, sealing, etc.) without copy-paste.
*/
package contracts

import (
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"

	composerapi "github.com/clearcompass-ai/judicial-network/api"
	"github.com/clearcompass-ai/judicial-network/api/exchange"
	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
	keysigner "github.com/clearcompass-ai/judicial-network/api/exchange/keystore/signer"
	"github.com/clearcompass-ai/judicial-network/api/judicial"
	"github.com/clearcompass-ai/judicial-network/api/verification"
	"github.com/clearcompass-ai/judicial-network/cases"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"

	tndavidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
)

const (
	scwE2EChainID     = "1"
	scwE2EDestination = tndavidson.ExchangeDID
	scwE2EOwnerDID    = "did:web:state:tn:davidson:clerk-mcclendon-eoa"
	scwE2EDocket      = "TN-DAV-2026-CR-00001"
)

// scwE2EAddr is the deterministic 20-byte address standing in for
// the deployed MinimalSCW contract. Distinct from the
// smart_contract_wallet_test.go's address so the two tests can run
// in the same package without aliasing.
func scwE2EAddr() [signatures.EthereumAddressLen]byte {
	var a [signatures.EthereumAddressLen]byte
	for i := range a {
		a[i] = byte(0xD0 + i)
	}
	return a
}

func scwE2EDID() string {
	addr := scwE2EAddr()
	return "did:pkh:eip155:" + scwE2EChainID + ":0x" + hex.EncodeToString(addr[:])
}

// scwE2EMagicReturn is the canonical EIP-1271 magic value
// (0x1626ba7e) padded to 32 bytes.
func scwE2EMagicReturn() []byte {
	out := make([]byte, 32)
	out[0], out[1], out[2], out[3] = 0x16, 0x26, 0xba, 0x7e
	return out
}

// scwE2EHarness bundles the composed listener + the controlling-EOA
// signer.Adapter + the SCW DID. Constructed once per test.
type scwE2EHarness struct {
	server  *composerapi.Server
	handler http.Handler
	signer  *keysigner.Adapter
	scwDID  string
}

// newSCWE2EHarness wires:
//   - memory keystore + controlling EOA generated under
//     scwE2EOwnerDID
//   - signer.Adapter bound to that EOA (Phase 8b)
//   - jurisdiction.Registry with Davidson registered + frozen
//   - composer (api.NewServer) with judicial mounted at /v1/judicial/
//   - judicial.SetCallerDIDResolver pinned to the SCW DID;
//     unwired in t.Cleanup
func newSCWE2EHarness(t *testing.T) *scwE2EHarness {
	t.Helper()

	ks := keystore.NewMemoryKeyStore()
	if _, err := ks.GenerateSecp256k1(scwE2EOwnerDID, "signing"); err != nil {
		t.Fatalf("GenerateSecp256k1: %v", err)
	}
	adapter, err := keysigner.New(ks, scwE2EOwnerDID)
	if err != nil {
		t.Fatalf("signer.New: %v", err)
	}

	reg := jurisdiction.NewRegistry()
	if err := reg.Register(tndavidson.MustBundle()); err != nil {
		t.Fatalf("registry.Register: %v", err)
	}
	reg.Freeze()

	srv, err := composerapi.NewServer(composerapi.Config{
		Addr: "127.0.0.1:0",
		Exchange: exchange.ServerConfig{
			KeyStore: ks,
		},
		Verification: verification.ServerConfig{},
		Judicial: judicial.ServerConfig{
			Deps: judicial.Dependencies{Registry: reg},
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	scwDID := scwE2EDID()
	judicial.SetCallerDIDResolver(func(*http.Request) string { return scwDID })
	t.Cleanup(func() { judicial.SetCallerDIDResolver(nil) })

	return &scwE2EHarness{
		server:  srv,
		handler: srv.Handler(),
		signer:  adapter,
		scwDID:  scwDID,
	}
}

// rebuildUnsignedEntry produces the same *envelope.Entry the
// case-initiate handler would build for the inputs we POSTed. The
// e2e test asserts that this entry's SigningPayload matches the
// signing_payload the API returned, byte-for-byte.
func rebuildUnsignedEntry(t *testing.T, signerDID, docket string, eventTime int64) *envelope.Entry {
	t.Helper()
	cfg := cases.InitiationConfig{
		Destination:  scwE2EDestination,
		SignerDID:    signerDID,
		DocketNumber: docket,
		CaseType:     "criminal",
		FiledDate:    "2026-01-15",
		EventTime:    eventTime,
	}
	res, err := cases.InitiateCase(cfg)
	if err != nil {
		t.Fatalf("InitiateCase (rebuild): %v", err)
	}
	return res.Entry
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
