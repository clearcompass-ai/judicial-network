/*
FILE PATH: cmd/judicial-cli/submit.go

DESCRIPTION:

	`submit` reads a JSON spec describing one judicial entry, builds
	the canonical wire bytes via the SDK envelope primitives, signs
	with the primary signer plus zero-or-more cosigners, and POSTs
	raw binary to the ledger's /v1/entries.

	The spec format is intentionally schema-agnostic — the ledger
	is "dumb writes" and we mirror that: judicial-cli does NOT
	validate domain payload fields. Walkthrough docs supply the
	correct JSON shape per schema.

WIRE FLOW (matches ledger/cmd/submit-stamp/main.go:283-307):
 1. payload_bytes := json.Marshal(spec.Payload)
 2. header := build ControlHeader from spec
 3. entry  := envelope.NewUnsignedEntry(header, payload_bytes)
 4. digest := sha256(envelope.SigningPayload(entry))
 5. sig0   := SignEntry(digest, primary_priv)
 6. for each cosigner: sig_n := SignEntry(digest, priv_n)
 7. entry.Signatures = [primary_sig, ...cosigner_sigs]
 8. entry.Validate()
 9. wire := envelope.Serialize(entry)
 10. POST wire as application/octet-stream → /v1/entries
 11. parse 202 SCT JSON; print sequence-tracking hash + log_time

SPEC JSON SHAPE:

	{
	  "schema":      "civil_case",                 // documentation hint only
	  "destination": "did:web:state:tn:davidson",  // ledger's LogDID
	  "primary_signer_key": "/path/to/clerk.key.json",
	  "cosigner_keys":      ["/path/to/cooper.key.json"],
	  "event_time_micros":  1705276800000000,       // optional; defaults to now()
	  "evidence_pointers": [                        // optional; cap 10
	    {"log_did": "did:web:state:tn:coa", "sequence": 1}
	  ],
	  "payload": { ... arbitrary domain JSON ... }
	}
*/
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	sdkenv "github.com/clearcompass-ai/attesta/core/envelope"
	sdksigs "github.com/clearcompass-ai/attesta/crypto/signatures"
	sdktypes "github.com/clearcompass-ai/attesta/types"
)

// SubmitSpec is the on-disk JSON shape that drives `submit`.
type SubmitSpec struct {
	Schema           string            `json:"schema"`
	Destination      string            `json:"destination"`
	PrimarySignerKey string            `json:"primary_signer_key"`
	CosignerKeys     []string          `json:"cosigner_keys,omitempty"`
	EventTimeMicros  int64             `json:"event_time_micros,omitempty"`
	EvidencePointers []EvidencePointer `json:"evidence_pointers,omitempty"`
	Payload          json.RawMessage   `json:"payload"`
}

// EvidencePointer mirrors types.LogPosition in JSON form, kept local
// so the spec file stays human-readable.
type EvidencePointer struct {
	LogDID   string `json:"log_did"`
	Sequence uint64 `json:"sequence"`
}

func runSubmit(args []string) error {
	fs := flagSet("submit")
	endpoint := fs.String("endpoint", "", "ledger base URL (e.g. http://localhost:8080)")
	specPath := fs.String("spec", "", "path to submission spec JSON")
	authToken := fs.String("token", "", "optional bearer token for Mode A admission")
	if err := fs.Parse(args); err != nil {
		return argsErr("parsing flags: %w", err)
	}
	if *endpoint == "" || *specPath == "" {
		return argsErr("--endpoint and --spec are required")
	}

	spec, err := loadSubmitSpec(*specPath)
	if err != nil {
		return argsErr("%v", err)
	}

	wire, canonicalHash, err := buildAndSign(spec)
	if err != nil {
		return wireErr("%v", err)
	}

	resp, status, err := postEntry(*endpoint, *authToken, wire)
	if err != nil {
		return transportErr("%v", err)
	}
	if status != http.StatusAccepted {
		return remoteErr("ledger returned HTTP %d: %s", status, string(resp))
	}

	// Echo SCT JSON to stdout, plus a one-liner with the
	// canonical hash a developer can plug into `judicial-cli wait`.
	fmt.Printf("canonical_hash=%s\n", hex.EncodeToString(canonicalHash[:]))
	fmt.Printf("status=accepted (HTTP 202)\n")
	fmt.Printf("sct=%s\n", string(resp))
	return nil
}

// loadSubmitSpec parses + validates the on-disk spec.
func loadSubmitSpec(path string) (*SubmitSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read spec %q: %w", path, err)
	}
	var spec SubmitSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parse spec %q: %w", path, err)
	}
	if spec.Destination == "" {
		return nil, fmt.Errorf("spec missing destination")
	}
	if spec.PrimarySignerKey == "" {
		return nil, fmt.Errorf("spec missing primary_signer_key")
	}
	if len(spec.Payload) == 0 || string(spec.Payload) == "null" {
		return nil, fmt.Errorf("spec missing payload")
	}
	if len(spec.EvidencePointers) > 10 {
		return nil, fmt.Errorf("evidence_pointers exceeds ledger cap of 10 (got %d)",
			len(spec.EvidencePointers))
	}
	return &spec, nil
}

// buildAndSign performs the wire-format pipeline. Returns the
// canonical bytes ready for POST plus the canonical-hash a caller
// can use to track sequencing via /v1/entries-hash.
//
// Per-signer signing path is chosen by the key file's did_method:
//   - "key"        : SignEntry      (64-byte r||s)        + SigAlgoECDSA
//   - "pkh-eip155" : signEthereumMsg (65-byte r||s||v EIP-191) + SigAlgoEIP191
//
// All signers (primary + cosigners) sign over the SAME signing-
// payload digest; the wallet-DID path simply wraps that digest
// in EIP-191 prefix before signing, so the verifier reconstructs
// the same prefix when ecrecover-checking.
func buildAndSign(spec *SubmitSpec) ([]byte, [32]byte, error) {
	var zero [32]byte

	// 1) Load primary signer.
	primaryDID, primaryMethod, primaryPriv, err := LoadKey(spec.PrimarySignerKey)
	if err != nil {
		return nil, zero, fmt.Errorf("load primary signer: %w", err)
	}

	// 2) Build header. AuthoritySameSigner is the simplest path
	//    when the entry's authority is just "this signer signed it";
	//    the walkthrough may attach delegation pointers for richer
	//    flows in a future iteration.
	auth := sdkenv.AuthoritySameSigner
	header := sdkenv.ControlHeader{
		SignerDID:     primaryDID,
		Destination:   spec.Destination,
		AuthorityPath: &auth,
		EventTime:     resolveEventTime(spec.EventTimeMicros),
	}
	if len(spec.EvidencePointers) > 0 {
		header.EvidencePointers = make([]sdktypes.LogPosition, 0, len(spec.EvidencePointers))
		for _, ep := range spec.EvidencePointers {
			header.EvidencePointers = append(header.EvidencePointers, sdktypes.LogPosition{
				LogDID:   ep.LogDID,
				Sequence: ep.Sequence,
			})
		}
	}

	// 3) Build the unsigned entry. Payload bytes are the JSON of
	//    spec.Payload — domain-opaque to the ledger, decoded by
	//    the verifier downstream.
	entry, err := sdkenv.NewUnsignedEntry(header, spec.Payload)
	if err != nil {
		return nil, zero, fmt.Errorf("NewUnsignedEntry: %w", err)
	}

	// 4) Hash the SigningPayload (preamble + header + payload, NO
	//    signatures). Every signer signs over this same digest.
	digest := sha256.Sum256(sdkenv.SigningPayload(entry))

	// 5) Primary signature first (Signatures[0].SignerDID must
	//    equal Header.SignerDID per envelope invariant).
	primarySig, primaryAlgo, err := signByMethod(primaryMethod, primaryPriv, digest)
	if err != nil {
		return nil, zero, fmt.Errorf("primary sign: %w", err)
	}
	entry.Signatures = []sdkenv.Signature{{
		SignerDID: primaryDID,
		AlgoID:    primaryAlgo,
		Bytes:     primarySig,
	}}

	// 6) Cosigners.
	for _, kp := range spec.CosignerKeys {
		cdid, cmethod, cpriv, err := LoadKey(kp)
		if err != nil {
			return nil, zero, fmt.Errorf("load cosigner %q: %w", kp, err)
		}
		csig, calgo, err := signByMethod(cmethod, cpriv, digest)
		if err != nil {
			return nil, zero, fmt.Errorf("cosigner %s sign: %w", cdid, err)
		}
		entry.Signatures = append(entry.Signatures, sdkenv.Signature{
			SignerDID: cdid,
			AlgoID:    calgo,
			Bytes:     csig,
		})
	}

	// 7) Validate end-to-end before serializing.
	if err := entry.Validate(); err != nil {
		return nil, zero, fmt.Errorf("entry.Validate: %w", err)
	}

	// 8) Canonical bytes + hash.
	canonical := sdkenv.Serialize(entry)
	hash := sha256.Sum256(canonical)
	return canonical, hash, nil
}

// resolveEventTime returns the spec value if set, or wall-clock
// microseconds otherwise. Ledger's freshness-tolerance gate
// rejects entries too far from now per
// exchange/policy.FreshnessInteractive (5 minutes by default).
func resolveEventTime(spec int64) int64 {
	if spec != 0 {
		return spec
	}
	return time.Now().UnixMicro()
}

// postEntry POSTs canonical bytes to ledger's /v1/entries.
func postEntry(endpoint, token string, wire []byte) ([]byte, int, error) {
	url := endpoint + "/v1/entries"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}
	return body, resp.StatusCode, nil
}

// signByMethod dispatches signing to the correct primitive based on
// the loaded key file's did_method.
//
// Returns (sig_bytes, algo_id, error). The verifier reads algo_id
// from the entry's Signature.AlgoID and selects the matching
// VerifySecp256k1* primitive on the read side.
//
// Method-to-algo mapping (kept in sync with PKHVerifier and KeyVerifier):
//   - "key", ""    -> SignEntry (64B)              + SigAlgoECDSA  (0x0001)
//   - "pkh-eip155" -> SignEthereumRecoverable(EIP-191 digest) (65B)
//   - SigAlgoEIP191 (0x0003)
//
// Adding a new DID method (e.g., "pkh-eip155-eip712" using EIP-712
// typed data, or full smart-contract-wallet EIP-1271) is a new
// case here plus matching support in PKHVerifier.
func signByMethod(method string, priv *ecdsa.PrivateKey, digest [32]byte) ([]byte, uint16, error) {
	switch method {
	case DIDMethodKey, "":
		sig, err := sdksigs.SignEntry(digest, priv)
		if err != nil {
			return nil, 0, fmt.Errorf("SignEntry: %w", err)
		}
		return sig, sdkenv.SigAlgoECDSA, nil

	case DIDMethodPKHEIP155:
		// did:pkh + EIP-191 path: wrap the canonical-hash digest in
		// the EIP-191 personal_sign prefix, sign with recoverable v,
		// label the signature SigAlgoEIP191. The verifier reconstructs
		// the same prefixed digest from the canonical hash and does
		// ecrecover against the address inside the did:pkh.
		eip191Digest := sdksigs.EIP191Digest(digest[:])
		sig, err := sdksigs.SignEthereumRecoverable(priv, eip191Digest)
		if err != nil {
			return nil, 0, fmt.Errorf("SignEthereumRecoverable: %w", err)
		}
		return sig, sdkenv.SigAlgoEIP191, nil

	default:
		return nil, 0, fmt.Errorf("unknown did_method %q (valid: %q, %q)",
			method, DIDMethodKey, DIDMethodPKHEIP155)
	}
}
