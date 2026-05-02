/*
FILE PATH: api/exchange/keystore/vault/vault_keystore.go

DESCRIPTION:
    HashiCorp Vault Transit native backend for keystore.KeyStore.
    This file owns the Config + KeyStore types, constructor, and the
    KeyStore-interface dispatch surface for both curves (secp256k1 +
    Ed25519). Curve-specific glue lives in vault_secp256k1.go and
    vault_ed25519.go; HTTP plumbing lives in vault_http.go.

    Vault Transit OSS supports `ecdsa-p256k1` since v1.18 (Sept 2024)
    and `ed25519` since v1.6 (Jan 2021); production deploys run latest
    Vault. Private keys never leave Vault; ExportForEscrow returns an
    explicit "not exportable" error.
*/
package vault

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
)

// Config configures a Vault Transit keystore. Mirrors
// api/config.VaultConfig; HTTPClient is an explicit override hook for
// tests (httptest.Server) and dev paths.
type Config struct {
	Address    string
	Token      string
	Mount      string // default "transit"
	HTTPClient *http.Client
}

// KeyStore is a keystore.KeyStore backed by Vault Transit native
// curves. Per-DID Vault key names are derived as
// "<sanitized-did>__<curve>" so Ed25519 + secp256k1 keys for the same
// DID coexist without name collisions.
type KeyStore struct {
	cfg Config
	hc  *http.Client

	mu      sync.RWMutex
	keysEd  map[string]*keystore.KeyInfo // did → ed25519 KeyInfo (cached)
	keysSec map[string]*keystore.KeyInfo // did → secp256k1 KeyInfo (cached)
}

// New constructs a Vault keystore. Address + Token are required;
// Mount defaults to "transit"; HTTPClient defaults to a 10s-timeout
// client. The constructor performs no network round-trip; the first
// real request happens when the caller invokes a Generate/Sign method.
func New(cfg Config) (*KeyStore, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault: address required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("vault: token required")
	}
	if cfg.Mount == "" {
		cfg.Mount = "transit"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &KeyStore{
		cfg:     cfg,
		hc:      hc,
		keysEd:  map[string]*keystore.KeyInfo{},
		keysSec: map[string]*keystore.KeyInfo{},
	}, nil
}

// LoadTokenFile reads a Vault token from disk. Production deploys
// always source the token from a sealed file rather than inline JSON;
// this helper centralises the trim/whitespace handling.
func LoadTokenFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("vault: read token file %q: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// keyName scrubs the DID for use as a Vault key name. Vault names
// disallow ":" and "/", which DIDs use heavily; we substitute "_".
// The "__" + curve suffix lets Ed25519 + secp256k1 keys for the same
// DID coexist on the same mount.
func keyName(did, curve string) string {
	scrub := strings.NewReplacer(":", "_", "/", "_", "#", "_").Replace(did)
	return fmt.Sprintf("%s__%s", scrub, curve)
}

// ─────────────────────────────────────────────────────────────────────
// keystore.KeyStore — management surface
// ─────────────────────────────────────────────────────────────────────

func (k *KeyStore) List() []*keystore.KeyInfo {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]*keystore.KeyInfo, 0, len(k.keysEd)+len(k.keysSec))
	for _, info := range k.keysEd {
		out = append(out, info)
	}
	for _, info := range k.keysSec {
		out = append(out, info)
	}
	return out
}

func (k *KeyStore) Rotate(did string, tier int) (*keystore.KeyInfo, error) {
	name := keyName(did, keystore.CurveSecp256k1)
	if err := k.do(http.MethodPost,
		fmt.Sprintf("/v1/%s/keys/%s/rotate", k.cfg.Mount, url.PathEscape(name)),
		nil, nil); err != nil {
		return nil, fmt.Errorf("vault: rotate: %w", err)
	}
	pub, err := k.fetchPublicKey(name, keystore.CurveSecp256k1)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	info := &keystore.KeyInfo{
		KeyID:        fmt.Sprintf("%s#secp256k1-%d", did, tier),
		DID:          did,
		Purpose:      "signing",
		Curve:        keystore.CurveSecp256k1,
		PublicKey:    pub,
		Created:      now,
		Rotated:      &now,
		RotationTier: tier,
	}
	k.mu.Lock()
	k.keysSec[did] = info
	k.mu.Unlock()
	return info, nil
}

func (k *KeyStore) Destroy(did string) error {
	var firstErr error
	for _, curve := range []string{keystore.CurveEd25519, keystore.CurveSecp256k1} {
		name := keyName(did, curve)
		if err := k.do(http.MethodDelete,
			fmt.Sprintf("/v1/%s/keys/%s", k.cfg.Mount, url.PathEscape(name)),
			nil, nil); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	k.mu.Lock()
	delete(k.keysEd, did)
	delete(k.keysSec, did)
	k.mu.Unlock()
	if firstErr != nil {
		return fmt.Errorf("vault: destroy: %w", firstErr)
	}
	return nil
}

// ExportForEscrow is unsupported: Vault Transit keys are non-exportable
// by design. Operators that need escrow ceremonies must run them
// against the in-memory keystore at bootstrap and then promote the
// resulting envelope into Vault.
func (k *KeyStore) ExportForEscrow(_ string) (ed25519.PrivateKey, error) {
	return nil, fmt.Errorf("vault: ExportForEscrow not supported (Vault Transit keys are non-exportable; run escrow at bootstrap)")
}
