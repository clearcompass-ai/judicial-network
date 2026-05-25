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

	J's authority is established on-log: the genesis admission authority (G,
	init-network's admission-authority.key) authorizes an admission_authority_v1
	snapshot that names J's address; thereafter the ledger's Current() keyset
	returns J. This file is agnostic to how J got authorized — it just signs.
*/
package handlers

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/clearcompass-ai/attesta/authz"
	"github.com/clearcompass-ai/attesta/core/envelope"
	sdksigs "github.com/clearcompass-ai/attesta/crypto/signatures"
)

// WriteAuthHeader carries the base64 authz.WriteAuthorization out-of-band on the
// single-submission path. It MUST byte-match the ledger's
// admission.WriteAuthHeader — this is the cross-repo wire contract (the JN does
// not import the ledger). Ledger: admission/write_auth_gate.go.
const WriteAuthHeader = "X-Attesta-Write-Authorization"

// AnchorFunc returns the cosigned tree-head root the authorization binds as its
// as-of anchor. Injected so tests can supply a deterministic anchor.
type AnchorFunc func() ([32]byte, error)

// AdmissionAuthorizer mints detached WriteAuthorizations with the JN's admission
// EOA (J). nil on Dependencies disables the attach (ungated logs / tests) — the
// forward path is then byte-for-byte the pre-gating proxy.
type AdmissionAuthorizer struct {
	priv   *ecdsa.PrivateKey
	anchor AnchorFunc
}

// NewAdmissionAuthorizer builds an authorizer from a loaded key + anchor source.
func NewAdmissionAuthorizer(priv *ecdsa.PrivateKey, anchor AnchorFunc) *AdmissionAuthorizer {
	return &AdmissionAuthorizer{priv: priv, anchor: anchor}
}

// LoadAdmissionAuthorizer loads J from a raw hex 32-byte secp256k1 scalar file
// (the init-network admission-authority.key dialect) and wires a ledger-backed
// anchor source (GET /v1/tree/head). Empty keyFile → (nil, nil): gating attach
// disabled, leaving the forward path unchanged.
func LoadAdmissionAuthorizer(keyFile, ledgerEndpoint string) (*AdmissionAuthorizer, error) {
	if strings.TrimSpace(keyFile) == "" {
		return nil, nil
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
	return &AdmissionAuthorizer{priv: priv, anchor: ledgerAnchor(ledgerEndpoint, 5*time.Second)}, nil
}

// Address returns J's 20-byte Ethereum address — the value that must be a member
// of the ledger's admission keyset (genesis fallback or on-log snapshot) for
// gate 5 to accept the authorizations this mints.
func (a *AdmissionAuthorizer) Address() ([20]byte, error) {
	return sdksigs.AddressFromPubkey(sdksigs.PubKeyBytes(&a.priv.PublicKey))
}

// MintHeader produces the WriteAuthHeader value for a signed entry: it computes
// the canonical entry identity (envelope.EntryIdentity == SHA-256(Serialize),
// matching the ledger's canonicalHash byte-for-byte), binds the current cosigned
// anchor, signs with J, and base64-encodes the fixed-width authorization.
func (a *AdmissionAuthorizer) MintHeader(signed []byte) (string, error) {
	entry, err := envelope.Deserialize(signed)
	if err != nil {
		return "", fmt.Errorf("admission authz: deserialize entry: %w", err)
	}
	entryIdentity, err := envelope.EntryIdentity(entry)
	if err != nil {
		return "", fmt.Errorf("admission authz: entry identity: %w", err)
	}
	anchor, err := a.anchor()
	if err != nil {
		return "", fmt.Errorf("admission authz: resolve anchor: %w", err)
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

// ledgerAnchor returns an AnchorFunc that fetches the ledger's current cosigned
// tree-head root (GET /v1/tree/head → root_hash hex), cached for ttl. The anchor
// pins the auditor's as-of re-derivation; the ledger verifies the signer against
// its CURRENT keyset and does not re-check the anchor (write_auth_gate.go), so a
// slightly-stale-but-valid head is safe.
func ledgerAnchor(endpoint string, ttl time.Duration) AnchorFunc {
	var (
		mu     sync.Mutex
		cached [32]byte
		at     time.Time
		loaded bool
	)
	return func() ([32]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		if loaded && time.Since(at) < ttl {
			return cached, nil
		}
		resp, err := ledgerSubmitClient.Get(endpoint + "/v1/tree/head")
		if err != nil {
			return [32]byte{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return [32]byte{}, fmt.Errorf("tree/head HTTP %d: %s", resp.StatusCode, body)
		}
		var th struct {
			RootHash string `json:"root_hash"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&th); err != nil {
			return [32]byte{}, fmt.Errorf("tree/head decode: %w", err)
		}
		rh, err := hex.DecodeString(th.RootHash)
		if err != nil || len(rh) != 32 {
			return [32]byte{}, fmt.Errorf("tree/head root_hash not 32-byte hex")
		}
		var out [32]byte
		copy(out[:], rh)
		cached, at, loaded = out, time.Now(), true
		return out, nil
	}
}
