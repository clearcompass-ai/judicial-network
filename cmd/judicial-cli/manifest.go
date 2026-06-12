/*
FILE PATH: cmd/judicial-cli/manifest.go

DESCRIPTION:

	`publish-manifest` — on-log publication of the network consumption
	manifest (networkbundle.Manifest). The manifest is projected from the SAME
	compiled jurisdiction.Bundle the SubmitGate enforces, serialized to its
	canonical bytes, and published as an entry whose Header.SchemaRef cites
	the manifest ANCHOR schema position — the exact pattern the admission
	keyset uses, so "current manifest" = the latest entry citing the anchor
	(GET /v1/query/schema_ref/{pos} on the ledger).

	Two-step bootstrap, mirroring LEDGER_ADMISSION_AUTHORITY_SCHEMA:

	  1. judicial-cli publish-manifest --publish-anchor ...   → anchor schema
	     entry; wait for its sequence (judicial-cli wait).
	  2. judicial-cli publish-manifest --anchor <log-did>@<seq> ... → the
	     manifest entry citing it. Re-run to publish amendments; the latest
	     citing entry is the current manifest.

	v1 publishes with Mode A payment (--token). Gated networks publish their
	manifest through their established governance write path (the
	admission-authority tooling mints the WriteAuthorization).
*/
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/baseproof/tooling/libs/networkbundle"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/baseproof/baseproof/builder"
	sdkenv "github.com/baseproof/baseproof/core/envelope"
	sdktypes "github.com/baseproof/baseproof/types"

	tncoa "github.com/clearcompass-ai/judicial-network/deployments/tn/coa"
	tndavidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/netmanifest"

	"github.com/baseproof/tooling/libs/cli"
)

// compiledBundle resolves the compiled-in Bundle + authoring overlay for a
// destination — the same factories cmd/network-api registers, so what is
// published is exactly what the gate enforces.
func compiledBundle(destination string) (jurisdiction.Bundle, map[string]networkbundle.OpOverlay, error) {
	switch destination {
	case tndavidson.ExchangeDID:
		return tndavidson.MustBundle(), trial.ManifestOverlay(), nil
	case tncoa.ExchangeDID:
		return tncoa.MustBundle(), nil, nil
	default:
		return nil, nil, fmt.Errorf("no compiled bundle for destination %q (known: %s, %s)",
			destination, tndavidson.ExchangeDID, tncoa.ExchangeDID)
	}
}

func runPublishManifest(args []string) error {
	fs := flagSet("publish-manifest")
	endpoint := fs.String("endpoint", "", "ledger base URL (required)")
	destination := fs.String("destination", tndavidson.ExchangeDID, "exchange DID whose manifest to publish")
	signerKey := fs.String("signer-key", "", "key file (judicial-cli keygen) signing the publication (required)")
	token := fs.String("token", "", "Mode A bearer token (empty → the ledger must accept unauthenticated writes)")
	anchor := fs.String("anchor", "", "manifest anchor schema position <log-did>@<seq> (required unless --publish-anchor)")
	publishAnchor := fs.Bool("publish-anchor", false, "publish the manifest ANCHOR schema entry instead (step 1 of 2)")
	networkName := fs.String("network-name", "", "network name for the manifest's network reference")
	ledgerURL := fs.String("ledger-url", "", "public ledger endpoint to declare in the manifest")
	gateURL := fs.String("gate-url", "", "public gate (network-api) endpoint to declare; empty ⇒ writes declared ledger-direct")
	if err := fs.Parse(args); err != nil {
		return argsErr("parsing flags: %w", err)
	}
	if *endpoint == "" || *signerKey == "" {
		return argsErr("--endpoint and --signer-key are required")
	}

	signerDID, method, priv, err := LoadKey(*signerKey)
	if err != nil {
		return argsErr("load signer key: %v", err)
	}

	// Step 1: the anchor schema entry (the position every manifest cites).
	if *publishAnchor {
		entry, bErr := builder.BuildSchemaEntry(builder.SchemaEntryParams{
			Destination: *destination,
			SignerDID:   signerDID,
			Parameters:  sdktypes.SchemaParameters{},
			EventTime:   time.Now().UTC().UnixMicro(),
		})
		if bErr != nil {
			return wireErr("build anchor schema entry: %v", bErr)
		}
		hash, sErr := signAndPost(*endpoint, *token, entry, signerDID, method, priv)
		if sErr != nil {
			return sErr
		}
		fmt.Printf("anchor schema submitted: canonical_hash=%s\n", hash)
		fmt.Printf("next: judicial-cli wait --endpoint %s --hash %s\n", *endpoint, hash)
		fmt.Printf("then: publish-manifest --anchor %s@<seq> ...\n", *destination)
		return nil
	}
	if *anchor == "" {
		return argsErr("--anchor <log-did>@<seq> is required (or --publish-anchor for step 1)")
	}
	anchorPos, err := parseAnchorPos(*anchor, *destination)
	if err != nil {
		return argsErr("%v", err)
	}

	// Step 2: project the manifest from the compiled bundle and publish it.
	b, overlay, err := compiledBundle(*destination)
	if err != nil {
		return argsErr("%v", err)
	}
	in := networkbundle.BuildInput{
		Network: networkbundle.NetworkRef{Name: *networkName},
		Overlay: overlay,
		Status: networkbundle.StatusProbes{
			Protocol: "ledger:/v1/entries-hash/{hash}",
			Finality: "ledger:/v1/tree/horizon",
			Domain:   "terminal entry of the instance's closed_by/amended_by chain",
		},
	}
	if *ledgerURL != "" {
		in.Endpoints = append(in.Endpoints, networkbundle.Endpoint{
			ID: "ledger", URL: *ledgerURL, Protocol: "baseproof-ledger/v1",
			Transport: networkbundle.Transport{TLS: "server-verify"}, Status: "/healthz",
		})
	}
	if *gateURL != "" {
		in.Endpoints = append(in.Endpoints, networkbundle.Endpoint{
			ID: "gate", URL: *gateURL, Protocol: "baseproof-exchange/v1",
			Transport: networkbundle.Transport{TLS: "mtls"}, Status: "/readyz",
			DependsOn: []string{"ledger"},
		})
		in.Admission = networkbundle.Admission{
			Payment: []string{"credit", "pow"}, Gating: "write-authorization", WriteVia: "gate",
		}
		in.Submit = networkbundle.Submit{Endpoint: "gate", Path: "/v1/entries/submit"}
	} else if *ledgerURL != "" {
		in.Admission = networkbundle.Admission{Payment: []string{"credit", "pow"}, WriteVia: "ledger"}
		in.Submit = networkbundle.Submit{Endpoint: "ledger", Path: "/v1/entries"}
	}
	m, err := netmanifest.Build(b, in)
	if err != nil {
		return wireErr("build manifest: %v", err)
	}
	payload, err := m.CanonicalBytes()
	if err != nil {
		return wireErr("canonical bytes: %v", err)
	}
	contentHash, err := m.ContentHash()
	if err != nil {
		return wireErr("content hash: %v", err)
	}

	auth := sdkenv.AuthoritySameSigner
	entry, err := sdkenv.NewUnsignedEntry(sdkenv.ControlHeader{
		SignerDID:     signerDID,
		Destination:   *destination,
		AuthorityPath: &auth,
		EventTime:     time.Now().UTC().UnixMicro(),
		SchemaRef:     &anchorPos,
	}, payload)
	if err != nil {
		return wireErr("new unsigned entry: %v", err)
	}
	hash, err := signAndPostEntry(*endpoint, *token, entry, signerDID, method, priv)
	if err != nil {
		return err
	}
	fmt.Printf("manifest published: exchange=%s operations=%d content_hash=%s\n",
		m.Exchange, len(m.Operations), hex.EncodeToString(contentHash[:]))
	fmt.Printf("entry canonical_hash=%s (anchor %s@%d)\n", hash, anchorPos.LogDID, anchorPos.Sequence)
	fmt.Printf("resolve: GET %s/v1/query/schema_ref/%s@%d — the LATEST citing entry is the current manifest\n",
		*endpoint, anchorPos.LogDID, anchorPos.Sequence)
	return nil
}

// signAndPost signs a builder-produced entry (rebuilding it unsigned first)
// and POSTs it. Returns the canonical hash hex.
func signAndPost(endpoint, token string, entry *sdkenv.Entry, signerDID, method string, priv *ecdsa.PrivateKey) (string, error) {
	u, err := sdkenv.NewUnsignedEntry(entry.Header, entry.DomainPayload)
	if err != nil {
		return "", wireErr("new unsigned entry: %v", err)
	}
	return signAndPostEntry(endpoint, token, u, signerDID, method, priv)
}

// signAndPostEntry signs over the SigningPayload with the loaded key (per its
// DID method), validates, serializes, and POSTs to /v1/entries — the same
// pipeline buildAndSign + postEntry use for `submit`.
func signAndPostEntry(endpoint, token string, u *sdkenv.Entry, signerDID, method string, priv *ecdsa.PrivateKey) (string, error) {
	digest := sha256.Sum256(sdkenv.SigningPayload(u))
	sig, algo, err := signByMethod(method, priv, digest)
	if err != nil {
		return "", wireErr("sign: %v", err)
	}
	u.Signatures = []sdkenv.Signature{{SignerDID: signerDID, AlgoID: algo, Bytes: sig}}
	if vErr := u.Validate(); vErr != nil {
		return "", wireErr("entry.Validate: %v", vErr)
	}
	wire, err := sdkenv.Serialize(u)
	if err != nil {
		return "", wireErr("serialize: %v", err)
	}
	hash, err := cli.SubmitWire(context.Background(), &http.Client{Timeout: 10 * time.Second}, endpoint, token, wire)
	if err != nil {
		return "", transportErr("%v", err)
	}
	return hash, nil
}

// parseAnchorPos parses <log-did>@<seq>; a bare @<seq> defaults to the
// destination's log.
func parseAnchorPos(arg, defaultLogDID string) (sdktypes.LogPosition, error) {
	at := strings.LastIndex(arg, "@")
	if at < 0 {
		return sdktypes.LogPosition{}, fmt.Errorf("--anchor %q must be <log-did>@<seq>", arg)
	}
	ld := arg[:at]
	if ld == "" {
		ld = defaultLogDID
	}
	seq, err := strconv.ParseUint(strings.TrimSpace(arg[at+1:]), 10, 64)
	if err != nil {
		return sdktypes.LogPosition{}, fmt.Errorf("--anchor sequence %q: not a uint64", arg[at+1:])
	}
	return sdktypes.LogPosition{LogDID: ld, Sequence: seq}, nil
}
