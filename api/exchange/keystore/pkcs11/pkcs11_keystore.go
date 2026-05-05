//go:build pkcs11

/*
FILE PATH: api/exchange/keystore/pkcs11/pkcs11_keystore.go

DESCRIPTION:

	PKCS#11 backend for keystore.KeyStore. This file owns the Config +
	KeyStore types, constructor / Close, and the management surface
	(List / Rotate / Destroy / ExportForEscrow). secp256k1 sign/gen
	glue lives in pkcs11_secp256k1.go; PKCS#11 object-find +
	EC_POINT plumbing lives in pkcs11_objects.go.

	Default deployment target is SoftHSMv2; the same code path drives
	any PKCS#11 v2.40 token that supports CKM_EC_KEY_PAIR_GEN +
	CKM_ECDSA with the secp256k1 OID curve parameter (1.3.132.0.10).

	Build tag: this file compiles ONLY with `-tags pkcs11`. The
	miekg/pkcs11 binding requires cgo + libpkcs11.so; default builds
	must remain cgo-free, so the unbuilt path is taken by
	pkcs11_stub.go.
*/
package pkcs11

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	mpkcs11 "github.com/miekg/pkcs11"

	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
)

// ErrEd25519Unsupported is returned by every Ed25519 entry point. The
// PKCS#11 mechanism for Ed25519 (CKM_EDDSA) is optional in v2.40 and
// missing from common SoftHSMv2 builds; deployments that need
// Ed25519 either keep that DID in MemoryKeyStore or in Vault.
var ErrEd25519Unsupported = errors.New("pkcs11: Ed25519 not supported (use Vault or MemoryKeyStore)")

var errNoKey = errors.New("pkcs11: no key for DID")

// Config configures a PKCS#11 keystore. PIN is the token user PIN —
// supply it at compose time from a sealed file.
type Config struct {
	LibraryPath string
	SlotID      uint
	PIN         string
	TokenLabel  string
}

// LoadPINFile reads the token PIN from disk; trims trailing
// whitespace. Production deploys always source the PIN from a sealed
// file rather than inline JSON.
func LoadPINFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("pkcs11: read PIN file %q: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// KeyStore is a keystore.KeyStore backed by a PKCS#11 token.
type KeyStore struct {
	cfg     Config
	ctx     *mpkcs11.Ctx
	session mpkcs11.SessionHandle

	mu      sync.RWMutex
	keysSec map[string]*keystore.KeyInfo
}

// New initializes the PKCS#11 module, opens a session, and logs in
// with the supplied PIN. Caller MUST invoke Close at shutdown to
// release the session.
func New(cfg Config) (*KeyStore, error) {
	if cfg.LibraryPath == "" {
		return nil, fmt.Errorf("pkcs11: library_path required")
	}
	if cfg.PIN == "" {
		return nil, fmt.Errorf("pkcs11: PIN required")
	}
	ctx := mpkcs11.New(cfg.LibraryPath)
	if ctx == nil {
		return nil, fmt.Errorf("pkcs11: failed to load %q", cfg.LibraryPath)
	}
	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("pkcs11: Initialize: %w", err)
	}
	session, err := ctx.OpenSession(cfg.SlotID,
		mpkcs11.CKF_SERIAL_SESSION|mpkcs11.CKF_RW_SESSION)
	if err != nil {
		_ = ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11: OpenSession slot %d: %w", cfg.SlotID, err)
	}
	if err := ctx.Login(session, mpkcs11.CKU_USER, cfg.PIN); err != nil {
		_ = ctx.CloseSession(session)
		_ = ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11: Login: %w", err)
	}
	return &KeyStore{
		cfg:     cfg,
		ctx:     ctx,
		session: session,
		keysSec: map[string]*keystore.KeyInfo{},
	}, nil
}

// Close releases the PKCS#11 session and finalizes the module. Idempotent.
func (k *KeyStore) Close() {
	if k.ctx == nil {
		return
	}
	_ = k.ctx.Logout(k.session)
	_ = k.ctx.CloseSession(k.session)
	_ = k.ctx.Finalize()
	k.ctx.Destroy()
	k.ctx = nil
}

// label returns the CKA_LABEL we attach to both halves of a key pair
// so we can find them again by DID.
func label(did string) []byte { return []byte("attesta:" + did) }

// ─────────────────────────────────────────────────────────────────────
// keystore.KeyStore — Ed25519 (unsupported)
// ─────────────────────────────────────────────────────────────────────

func (k *KeyStore) Generate(_ string, _ string) (*keystore.KeyInfo, error) {
	return nil, ErrEd25519Unsupported
}
func (k *KeyStore) Sign(_ string, _ []byte) ([]byte, error) { return nil, ErrEd25519Unsupported }
func (k *KeyStore) PublicKey(_ string) (ed25519.PublicKey, error) {
	return nil, ErrEd25519Unsupported
}

// ─────────────────────────────────────────────────────────────────────
// keystore.KeyStore — management
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

func (k *KeyStore) Rotate(did string, tier int) (*keystore.KeyInfo, error) {
	if err := k.Destroy(did); err != nil && !errors.Is(err, errNoKey) {
		return nil, err
	}
	info, err := k.GenerateSecp256k1(did, "signing")
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	info.RotationTier = tier
	info.Rotated = &now
	info.KeyID = fmt.Sprintf("%s#secp256k1-%d", did, tier)
	k.mu.Lock()
	k.keysSec[did] = info
	k.mu.Unlock()
	return info, nil
}

func (k *KeyStore) Destroy(did string) error {
	pubH, errPub := k.findPublicKey(did)
	privH, errPriv := k.findPrivateKey(did)
	if errPub != nil && errPriv != nil {
		return errNoKey
	}
	if errPub == nil {
		_ = k.ctx.DestroyObject(k.session, pubH)
	}
	if errPriv == nil {
		_ = k.ctx.DestroyObject(k.session, privH)
	}
	k.mu.Lock()
	delete(k.keysSec, did)
	k.mu.Unlock()
	return nil
}

// ExportForEscrow is unsupported: PKCS#11 keys with CKA_EXTRACTABLE=false
// (which is what we always generate) cannot be exported. Same rationale
// as Vault: route escrow through bootstrap.
func (k *KeyStore) ExportForEscrow(_ string) (ed25519.PrivateKey, error) {
	return nil, fmt.Errorf("pkcs11: ExportForEscrow not supported (token keys are non-extractable)")
}
