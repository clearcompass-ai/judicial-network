/*
netmanifest/roundtrip_rc10_test.go — the PRE-3 proof JN owed: every
production bundle's manifest, fully populated (Auth + network identity +
driveable-datatype anchors), round-trips through the CONSUMER door
(networkbundle.VerifyManifest) — and the same manifest WITHOUT anchors is
refused by name. The door's strictness is the oracle; this test is the
machine check that JN's population path satisfies it.
*/
package netmanifest

import (
	"strings"
	"testing"

	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/tooling/libs/networkbundle"

	deployregistry "github.com/clearcompass-ai/judicial-network/deployments/registry"
)

func testBootstrap(t *testing.T) *network.BootstrapDocument {
	t.Helper()
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return &network.BootstrapDocument{
		ProtocolVersion: "1", ExchangeDID: "did:web:exchange.example", NetworkName: "jn-roundtrip",
		GenesisWitnessSet:           []string{kp.DID},
		GenesisQuorumK:              1,
		GenesisTreeHead:             network.GenesisTreeHead{RootHash: strings.Repeat("0", 64), TreeSize: 0},
		GenesisAdmissionAuthorities: []string{"0123456789abcdef0123456789abcdef01234567"},
		GenesisAdmissionPolicy:      network.GenesisAdmissionPolicy{GatingRequired: true, CostMode: "uncharged"},
		GenesisSignaturePolicy:      network.SignaturePolicy{AllowedEntrySigSchemes: []uint16{0x0001}, AllowedCosignSchemeTags: []uint8{0x01}, MinSignaturesPerEntry: 1},
	}
}

func TestRC10_EveryBundleManifest_RoundTripsTheDoor(t *testing.T) {
	doc := testBootstrap(t)
	ids, err := doc.IDs()
	if err != nil {
		t.Fatal(err)
	}
	netIDHex := ""
	for _, b := range ids.NetworkID {
		netIDHex += string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&0xf])
	}

	for _, b := range deployregistry.LoadAll() {
		t.Run(b.ExchangeDID(), func(t *testing.T) {
			in := networkbundle.BuildInput{
				Network: networkbundle.NetworkRef{Name: "jn-roundtrip", NetworkID: netIDHex},
				Endpoints: []networkbundle.Endpoint{
					{ID: "ledger", URL: "https://ledger.example", Protocol: "baseproof-ledger/v1",
						Auth: networkbundle.AuthNone, Transport: networkbundle.Transport{TLS: "server-verify"}},
					{ID: "gate", URL: "https://gate.example", Protocol: "baseproof-exchange/v1",
						Auth: networkbundle.AuthSignedEnvelope, Transport: networkbundle.Transport{TLS: "mtls"}},
				},
				Submit: networkbundle.Submit{Endpoint: "gate", Path: "/v1/entries/submit"},
				Status: networkbundle.StatusProbes{Protocol: "p", Finality: "f", Domain: "d"},
			}
			m, err := Build(b, in)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			// Populate the driveable anchors the way production must:
			// every datatype an operation names gets its on-log triple.
			for i := range m.Datatypes {
				m.Datatypes[i].LogDID = "did:baseproof:log:jn"
				m.Datatypes[i].Sequence = uint64(i) + 100
				m.Datatypes[i].ContentHash = strings.Repeat("ab", 32)
			}
			raw, err := m.CanonicalBytes()
			if err != nil {
				t.Fatalf("canonical: %v", err)
			}
			if _, err := networkbundle.VerifyManifest(raw, doc); err != nil {
				t.Fatalf("THE ROUND-TRIP PROOF FAILED — a fully-populated %s manifest was refused by the consumer door: %v", b.ExchangeDID(), err)
			}

			// The negative half: strip ONE driveable anchor — the door must
			// refuse, naming the operation (the fail-closed claim, locked).
			if len(m.Datatypes) > 0 {
				m.Datatypes[0].LogDID, m.Datatypes[0].Sequence, m.Datatypes[0].ContentHash = "", 0, ""
				rawBad, err := m.CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := networkbundle.VerifyManifest(rawBad, doc); err == nil ||
					!strings.Contains(err.Error(), "without an on-log anchor") {
					t.Fatalf("an anchor-less driveable datatype must refuse by name: %v", err)
				}
			}
		})
	}
}
