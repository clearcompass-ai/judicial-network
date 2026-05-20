/*
FILE PATH: api/exchange/keystore/vault/vault_http.go

DESCRIPTION:

	Vault HTTP plumbing for the Transit-backed keystore. Owns:
	  - createKey: POST /v1/{mount}/keys/{name}
	  - fetchPublicKey: GET /v1/{mount}/keys/{name} (latest version)
	  - signDER: POST /v1/{mount}/sign/{name} (ASN.1-marshaled ECDSA)
	  - signEd25519: POST /v1/{mount}/sign/{name} (raw Ed25519)
	  - parsePublicKeyPEM: PKIX → 65-byte uncompressed (secp) or 32-byte (ed25519)
	  - do: shared transport with X-Vault-Token + non-2xx body capture
*/
package vault

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
)

// secp256k1Curve is the OID Vault uses inside SubjectPublicKeyInfo
// for ecdsa-p256k1 keys (1.3.132.0.10 / RFC 5480). The stdlib
// crypto/x509 has no awareness of this curve, so we decode the SPKI
// envelope by hand.
var (
	oidIDECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSecp256k1     = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

type ecPublicKeyPKIX struct {
	Algo struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.ObjectIdentifier
	}
	PubKey asn1.BitString
}

func (k *KeyStore) createKey(name, vaultType string) error {
	body := map[string]any{
		"type":             vaultType,
		"deletion_allowed": true,
		"exportable":       false,
		"derived":          false,
	}
	return k.do(http.MethodPost,
		fmt.Sprintf("/v1/%s/keys/%s", k.cfg.Mount, url.PathEscape(name)),
		body, nil)
}

func (k *KeyStore) fetchPublicKey(name, curve string) ([]byte, error) {
	var resp struct {
		Data struct {
			LatestVersion int `json:"latest_version"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := k.do(http.MethodGet,
		fmt.Sprintf("/v1/%s/keys/%s", k.cfg.Mount, url.PathEscape(name)),
		nil, &resp); err != nil {
		return nil, fmt.Errorf("vault: fetchPublicKey: %w", err)
	}
	versionKey := fmt.Sprintf("%d", resp.Data.LatestVersion)
	entry, ok := resp.Data.Keys[versionKey]
	if !ok || entry.PublicKey == "" {
		return nil, fmt.Errorf("vault: fetchPublicKey: missing latest version %s", versionKey)
	}
	return parsePublicKeyPEM(entry.PublicKey, curve)
}

func parsePublicKeyPEM(pemStr, curve string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("vault: parsePublicKeyPEM: no PEM block")
	}
	switch curve {
	case keystore.CurveSecp256k1:
		// Stdlib x509 doesn't know secp256k1; ASN.1-decode the SPKI
		// envelope ourselves and pull the raw uncompressed point out
		// of the BIT STRING.
		var spki ecPublicKeyPKIX
		if _, err := asn1.Unmarshal(block.Bytes, &spki); err != nil {
			return nil, fmt.Errorf("vault: parsePublicKeyPEM: %w", err)
		}
		if !spki.Algo.Algorithm.Equal(oidIDECPublicKey) {
			return nil, fmt.Errorf("vault: parsePublicKeyPEM: not id-ecPublicKey: %s",
				spki.Algo.Algorithm.String())
		}
		if !spki.Algo.Parameters.Equal(oidSecp256k1) {
			return nil, fmt.Errorf("vault: parsePublicKeyPEM: not secp256k1 OID: %s",
				spki.Algo.Parameters.String())
		}
		raw := spki.PubKey.Bytes
		if len(raw) != 65 || raw[0] != 0x04 {
			return nil, fmt.Errorf("vault: parsePublicKeyPEM: bad point: len=%d prefix=%x",
				len(raw), raw[:1])
		}
		out := make([]byte, 65)
		copy(out, raw)
		return out, nil
	}
	return nil, fmt.Errorf("vault: parsePublicKeyPEM: unknown curve %q", curve)
}

func (k *KeyStore) signDER(name string, digest []byte) (*big.Int, *big.Int, error) {
	body := map[string]any{
		"input":                base64.StdEncoding.EncodeToString(digest),
		"prehashed":            true,
		"marshaling_algorithm": "asn1",
	}
	var resp struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := k.do(http.MethodPost,
		fmt.Sprintf("/v1/%s/sign/%s", k.cfg.Mount, url.PathEscape(name)),
		body, &resp); err != nil {
		return nil, nil, fmt.Errorf("vault: signDER: %w", err)
	}
	sig := stripVaultPrefix(resp.Data.Signature)
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: signDER decode: %w", err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(raw, &rs); err != nil {
		return nil, nil, fmt.Errorf("vault: signDER asn1: %w", err)
	}
	if rs.R == nil || rs.S == nil {
		return nil, nil, fmt.Errorf("vault: signDER: nil R/S")
	}
	return rs.R, canonicalizeS(rs.S), nil
}

// stripVaultPrefix drops the "vault:vN:" envelope Vault Transit puts
// in front of every signature (and ciphertext) it returns.
func stripVaultPrefix(s string) string {
	if i := strings.LastIndex(s, ":"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// do executes a Vault HTTP call. body may be nil; out may be nil.
// Wraps non-2xx responses in an error containing the body.
func (k *KeyStore) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("vault: marshal: %w", err)
		}
		rd = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, strings.TrimRight(k.cfg.Address, "/")+path, rd)
	if err != nil {
		return fmt.Errorf("vault: new request: %w", err)
	}
	req.Header.Set("X-Vault-Token", k.cfg.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.hc.Do(req)
	if err != nil {
		return fmt.Errorf("vault: do: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("vault: %s %s: %d: %s", method, path, resp.StatusCode, string(respBody))
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("vault: decode: %w", err)
		}
	}
	return nil
}
