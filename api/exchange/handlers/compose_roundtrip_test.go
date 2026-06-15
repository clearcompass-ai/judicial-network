/*
FILE PATH: api/exchange/handlers/compose_roundtrip_test.go

DESCRIPTION:

	The drift-proof: an entry AUTHORED by jurisdiction.Compose — from the REAL
	Davidson bundle's cosignature + prerequisite policies + its EntryTemplates —
	then signed via the shared entryspec.BuildAndSign pipeline, is ADMITTED by the
	REAL BundleSubmitGate. Producer and validator are the SAME policies facing
	opposite directions, so this test permanently pins them against each other.
	No docker: the gate stands on payload + signatures + policy alone.

	Scoped to ORIGIN events (case_initiation) — what entryspec's same-signer
	authority expresses today. The companion test proves Compose's authoring-time
	prerequisite walk REFUSES dependent events until a case context is supplied
	(the v0.7.0 case-root scanner), which is the same EvalContext the gate consumes.
*/
package handlers

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/tooling/libs/entryspec"

	davidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/verification"
)

// mintKey writes a did:key KeyFile (entryspec format) and returns (did, path).
func mintKey(t *testing.T, dir, name string) (did, path string) {
	t.Helper()
	pair, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}
	b := make([]byte, 32)
	pair.PrivateKey.D.FillBytes(b)
	kf := entryspec.KeyFile{
		DID:                    pair.DID,
		DIDMethod:              entryspec.DIDMethodKey,
		PrivateKeyHex:          hex.EncodeToString(b),
		PublicKeyCompressedHex: hex.EncodeToString(pair.PublicKeyCompressed),
	}
	body, _ := json.MarshalIndent(kf, "", "  ")
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return pair.DID, path
}

// TestComposeRoundTrip_CaseInitiation: Compose → BuildAndSign → Admit must pass.
func TestComposeRoundTrip_CaseInitiation(t *testing.T) {
	reg := davidsonRegistry(t)
	b := davidson.MustBundle()

	dir := t.TempDir()
	clerk1DID, clerk1Key := mintKey(t, dir, "clerk1.json") // primary (Signatures[0])
	clerk2DID, clerk2Key := mintKey(t, dir, "clerk2.json") // cosigner of record

	cast := jurisdiction.Cast{
		Primary: jurisdiction.CastMember{Role: "court_clerk", DID: clerk1DID, KeyFile: clerk1Key},
		Cosigners: []jurisdiction.CastMember{
			{Role: "court_clerk", DID: clerk2DID, KeyFile: clerk2Key, Exchange: davidson.ExchangeDID},
		},
	}
	spec, err := jurisdiction.Compose(b, "case_initiation", cast, nil, jurisdiction.Values{
		"docket_number": "2027-CV-100",
		"caption":       "Doe v. Roe",
		"specialty":     "civil",
	})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if spec.Destination != davidson.ExchangeDID || spec.PrimarySignerKey != clerk1Key {
		t.Fatalf("spec wiring: destination=%q primary=%q", spec.Destination, spec.PrimarySignerKey)
	}

	wire, _, err := entryspec.BuildAndSign(spec)
	if err != nil {
		t.Fatalf("BuildAndSign: %v", err)
	}

	// Trust-mode resolver: pins the cosignature threshold, not chain verification.
	gate := &BundleSubmitGate{
		Registry: reg,
		Resolver: verification.NewMapRoleResolver().Bind(clerk2DID, "court_clerk", davidson.ExchangeDID),
	}
	if rej := gate.Admit(context.Background(), wire); rej != nil {
		t.Fatalf("composed case_initiation REJECTED by gate: code=%q reason=%q", rej.Code, rej.Reason)
	}
}

// TestComposeRoundTrip_DependentEventRefused: Compose's authoring-time
// prerequisite walk refuses counsel_appearance (needs a case_initiation
// ancestor) with no case context — composable once the scanner feeds context.
func TestComposeRoundTrip_DependentEventRefused(t *testing.T) {
	b := davidson.MustBundle()
	cast := jurisdiction.Cast{
		Primary: jurisdiction.CastMember{Role: "court_clerk", DID: "did:key:zPRIMARY", KeyFile: "primary.json"},
	}
	_, err := jurisdiction.Compose(b, "counsel_appearance", cast, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "prerequisite") {
		t.Fatalf("want authoring-time prerequisite refusal, got %v", err)
	}
}
