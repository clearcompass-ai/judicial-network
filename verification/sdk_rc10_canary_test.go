/*
verification/sdk_rc10_canary_test.go — the pin canary for SDK v0.0.5-rc1.

The sdk-version-pin workflow asserts the go.mod LINE; this test asserts the
CONTENT: the pinned SDK actually ships the rc10 registry expansion JN's
PRE-4a/PRE-13 waves build on. If someone "bumps" to a fork or a stale proxy
copy that lacks rc10, the pin line can lie — this canary cannot. It
exercises one real encode→decode round-trip per new family plus the burn
authority surface, so a regressive SDK fails here, not three waves later.
*/
package verification

import (
	"testing"

	"github.com/baseproof/baseproof/credential"
	"github.com/baseproof/baseproof/delegation"
	"github.com/baseproof/baseproof/exchange"
	"github.com/baseproof/baseproof/kinds"
	"github.com/baseproof/baseproof/network"
)

func TestSDKPinDeliversRC10Surface(t *testing.T) {
	// The seven rc10 constants exist in the closed catalog.
	for _, k := range []string{
		kinds.EntryExchangeGenesisV1,
		kinds.EntryDestinationProvisionV1,
		kinds.EntryDestinationAmendV1,
		kinds.EntryDestinationRetireV1,
		kinds.EntryDelegationGrantV1,
		kinds.EntryCredentialAttestationV1,
		kinds.EntryNetworkBurnV1,
	} {
		if k == "" {
			t.Fatal("an rc10 kind constant is empty — the pinned SDK is not rc10")
		}
	}

	// One real round-trip per family JN will gate/project.
	var nid [32]byte
	nid[0] = 1
	if raw, err := exchange.EncodeExchangeGenesisPayload(exchange.ExchangeGenesis{
		ExchangeDID: "did:web:exchange.example", NetworkID: nid,
	}); err != nil {
		t.Fatalf("exchange genesis encode: %v", err)
	} else if _, err := exchange.DecodeExchangeGenesisPayload(raw); err != nil {
		t.Fatalf("exchange genesis decode: %v", err)
	}

	if raw, err := exchange.EncodeDestinationProvisionPayload(exchange.DestinationProvision{
		DestinationRef: "tn/davidson/circuit-1", ExchangeDID: "did:web:exchange.example",
		Endpoints: map[string]string{"filing": "https://circuit-1.davidson.example"},
	}); err != nil {
		t.Fatalf("provision encode: %v", err)
	} else if _, err := exchange.DecodeDestinationProvisionPayload(raw); err != nil {
		t.Fatalf("provision decode: %v", err)
	}

	if raw, err := delegation.EncodeDelegationGrantPayload(delegation.DelegationGrant{
		OriginRef: "did:web:exchange.example", Subject: "tn/davidson/circuit-1",
		Delegate: "did:pkh:eip155:1:0xabc", Role: "clerk",
	}); err != nil {
		t.Fatalf("grant encode: %v", err)
	} else if _, err := delegation.DecodeDelegationGrantPayload(raw); err != nil {
		t.Fatalf("grant decode: %v", err)
	}

	var vh [32]byte
	vh[0] = 2
	if raw, err := credential.EncodeCredentialAttestationPayload(credential.CredentialAttestation{
		Issuer: "did:web:bar.example", Subject: "did:pkh:eip155:1:0xabc",
		CredentialKey: "bar_license", ValueHash: vh,
	}); err != nil {
		t.Fatalf("attestation encode: %v", err)
	} else if _, err := credential.DecodeCredentialAttestationPayload(raw); err != nil {
		t.Fatalf("attestation decode: %v", err)
	}

	// The burn AUTHORITY surface (W1): an unsigned burn must be structurally
	// invalid — if this encode ever succeeds, the pinned SDK predates the
	// quorum requirement and every burn consumer JN trusts is unsafe.
	if _, err := network.EncodeNetworkBurnPayload(network.NetworkBurn{
		NetworkID: nid, ReasonClass: "x",
	}); err == nil {
		t.Fatal("an UNSIGNED burn encoded successfully — the pinned SDK lacks the W1 authority model")
	}
}
