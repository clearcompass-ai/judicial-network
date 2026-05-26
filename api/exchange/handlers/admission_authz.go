/*
FILE PATH: api/exchange/handlers/admission_authz.go

DESCRIPTION:

	The JN's GATING attestation — step 2 of "JN implements gating".

	  1. DECIDE  (semantic): SubmitGate.Admit runs the destination Bundle's
	     cosignature + prerequisite policy → accept/reject.            (submit_gate.go)
	  2. ATTEST  (cryptographic, HERE): after accept, mint a detached
	     authz.WriteAuthorization over the entry's canonical identity, signed
	     with the JN's on-log admission EOA (J).
	  3. ENFORCE (structural): the ledger's gate 5 ecrecovers J, checks it
	     against the CURRENT on-log admission keyset, and DROPS the proof —
	     never sequenced, never stored.                       (ledger admission/)

	The authorization is carried OUT-OF-BAND in the WriteAuthHeader and is
	NEVER part of the entry's canonical bytes, so gating leaves zero footprint
	on the log: the per-write token is ephemeral; only the rare governance
	(the admission_authority_v1 keyset that registers J) lives on-log.

	ZERO-TRUST ANCHOR. The as-of anchor MUST come from a WITNESS-COSIGNED,
	verified horizon — never the ledger's unverified word. The JN exists to
	hold the ledger accountable (verification/verifying_leaf_reader.go: "trust
	the witness quorum, not the ledger's word"), so the anchor source is an
	injected AnchorFunc backed by sdklog.FetchVerifiedHorizon (K-of-N cosig,
	fail-closed). There is deliberately NO built-in raw /v1/tree/head reader:
	an authorizer cannot be constructed with a ledger-trusting anchor.
*/
package handlers

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/clearcompass-ai/attesta/authz"
	"github.com/clearcompass-ai/attesta/core/envelope"
	sdksigs "github.com/clearcompass-ai/attesta/crypto/signatures"
)

// WriteAuthHeader carries the base64 authz.WriteAuthorization out-of-band on the
// single-submission path. It MUST byte-match the ledger's
// admission.WriteAuthHeader — this is the cross-repo wire contract (the JN does
// not import the ledger). Ledger: admission/write_auth_gate.go.
const WriteAuthHeader = "X-Attesta-Write-Authorization"

// AnchorFunc returns the WITNESS-COSIGNED, verified tree-head root for logDID —
// the as-of anchor an authorization binds. It MUST verify the K-of-N witness
// cosignature and fail closed (never return an unverified root). Wired in
// main.go from sdklog.HTTPCheckpointClient.FetchVerifiedHorizon over the per-log
// cosign.WitnessKeySet — the same trust root VerifyingLeafReader uses.
type AnchorFunc func(logDID string) ([32]byte, error)

// AdmissionAuthorizer mints detached WriteAuthorizations with the JN's admission
// EOA (J). nil on Dependencies disables the attach (ungated logs / tests) — the
// forward path is then byte-for-byte the pre-gating proxy.
type AdmissionAuthorizer struct {
	priv   *ecdsa.PrivateKey
	anchor AnchorFunc
}

// NewAdmissionAuthorizer builds an authorizer from a loaded key + a verified
// anchor source. anchor MUST be non-nil (a nil anchor would mean "no trust
// step", which violates the JN's zero-trust posture).
func NewAdmissionAuthorizer(priv *ecdsa.PrivateKey, anchor AnchorFunc) *AdmissionAuthorizer {
	return &AdmissionAuthorizer{priv: priv, anchor: anchor}
}

// LoadAdmissionAuthorizer loads J from a raw hex 32-byte secp256k1 scalar file
// (the init-network admission-authority.key dialect) and binds the supplied
// VERIFIED anchor source. Empty keyFile → (nil, nil): gating attach disabled,
// leaving the forward path unchanged. A non-empty keyFile with a nil anchor is
// rejected — fail-closed: the JN must never mint an authorization over an
// unverified anchor.
func LoadAdmissionAuthorizer(keyFile string, anchor AnchorFunc) (*AdmissionAuthorizer, error) {
	if strings.TrimSpace(keyFile) == "" {
		return nil, nil
	}
	if anchor == nil {
		return nil, fmt.Errorf("admission authorizer: a verified anchor source is required (refusing a ledger-trusting default)")
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("admission authority key %q: %w", keyFile, err)
	}
	scalar, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(scalar) != 32 {
		return nil, fmt.Errorf("admission authority key %q: want a 32-byte hex scalar", keyFile)
	}
	priv, err := sdksigs.PrivKeyFromBytes(scalar)
	if err != nil {
		return nil, fmt.Errorf("admission authority key %q: %w", keyFile, err)
	}
	return &AdmissionAuthorizer{priv: priv, anchor: anchor}, nil
}

// Address returns J's 20-byte Ethereum address — the value that must be a member
// of the ledger's admission keyset (genesis fallback or on-log snapshot) for
// gate 5 to accept the authorizations this mints.
func (a *AdmissionAuthorizer) Address() ([20]byte, error) {
	return sdksigs.AddressFromPubkey(sdksigs.PubKeyBytes(&a.priv.PublicKey))
}

// MintHeader produces the WriteAuthHeader value for a signed entry: it computes
// the canonical entry identity (envelope.EntryIdentity == SHA-256(Serialize),
// matching the ledger's canonicalHash byte-for-byte), binds the WITNESS-VERIFIED
// anchor for the entry's destination log, signs with J, and base64-encodes the
// fixed-width authorization. Fails closed if the anchor can't be verified.
func (a *AdmissionAuthorizer) MintHeader(signed []byte) (string, error) {
	entry, err := envelope.Deserialize(signed)
	if err != nil {
		return "", fmt.Errorf("admission authz: deserialize entry: %w", err)
	}
	entryIdentity, err := envelope.EntryIdentity(entry)
	if err != nil {
		return "", fmt.Errorf("admission authz: entry identity: %w", err)
	}
	anchor, err := a.anchor(entry.Header.Destination)
	if err != nil {
		return "", fmt.Errorf("admission authz: verified anchor for %q: %w", entry.Header.Destination, err)
	}
	wa, err := authz.SignWriteAuthorization(a.priv, entry.Header.Destination, entryIdentity, anchor)
	if err != nil {
		return "", fmt.Errorf("admission authz: sign: %w", err)
	}
	enc, err := wa.Encode()
	if err != nil {
		return "", fmt.Errorf("admission authz: encode: %w", err)
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}
