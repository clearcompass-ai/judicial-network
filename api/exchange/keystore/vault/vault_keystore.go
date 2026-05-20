/*
FILE PATH: api/exchange/keystore/vault/vault_keystore.go

DESCRIPTION:

	HashiCorp Vault Transit native backend for keystore.KeyStore
	(secp256k1-only). Owns the Config + KeyStore types, constructor, and
	the management surface; curve glue lives in vault_secp256k1.go, HTTP
	plumbing in vault_http.go.

	Vault Transit OSS supports `ecdsa-p256k1` since v1.18 (Sept 2024);
	production deploys run latest Vault. Private keys never leave Vault;
	ExportForEscrow returns an explicit "not exportable" error, and staged
	rotation (StageNextKey/CommitRotation) is likewise unsupported here —
	the in-memory backend is the network-api wired keystore; Vault deploys
	rotate at bootstrap.
*/
package vault

import (
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

// KeyStore is a keystore.KeyStore backed by Vault Transit secp256k1 keys.
// Per-DID Vault key names are derived as "<sanitized-did>__secp256k1".
type KeyStore struct {
	cfg Config
	hc  *http.Client

	mu      sync.RWMutex
	keysSec map[string]*keystore.KeyInfo // did → secp256k1 KeyInfo (cached)
}

// New constructs a Vault keystore. Address + Token are required; Mount
// defaults to "transit"; HTTPClient defaults to a 10s-timeout client. No
// network round-trip until the first Generate/Sign.
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
		keysSec: map[string]*keystore.KeyInfo{},
	}, nil
}

// LoadTokenFile reads a Vault token from disk.
func LoadTokenFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("vault: read token file %q: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// keyName scrubs the DID for use as a Vault key name (": / #" → "_").
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
	out := make([]*keystore.KeyInfo, 0, len(k.keysSec))
	for _, info := range k.keysSec {
		out = append(out, info)
	}
	return out
}

func (k *KeyStore) Destroy(did string) error {
	name := keyName(did, keystore.CurveSecp256k1)
	err := k.do(http.MethodDelete,
		fmt.Sprintf("/v1/%s/keys/%s", k.cfg.Mount, url.PathEscape(name)),
		nil, nil)
	k.mu.Lock()
	delete(k.keysSec, did)
	k.mu.Unlock()
	if err != nil {
		return fmt.Errorf("vault: destroy: %w", err)
	}
	return nil
}

// ExportForEscrow is unsupported: Vault Transit keys are non-exportable
// by design. Escrow ceremonies run against the in-memory keystore at
// bootstrap.
func (k *KeyStore) ExportForEscrow(_ string) ([]byte, error) {
	return nil, fmt.Errorf("vault: ExportForEscrow not supported (Vault Transit keys are non-exportable; run escrow at bootstrap)")
}
