/*
FILE PATH: cases/artifact/publish.go
DESCRIPTION: Encrypts artifacts and pushes ciphertext to content store. Dispatches
    between AES-256-GCM and Umbral PRE based on schema artifact_encryption field.
KEY ARCHITECTURAL DECISIONS:
    - TWO KEY STORES: ArtifactKeyStore (SDK, 44-byte ArtifactKey) and
      DelegationKeyStore (judicial-network, ~113-byte ECIES ciphertext).
    - PRE DELEGATION KEY PATTERN: Master key NEVER enters PRE operations.
    - FLAG 1 FIX: resolvePublicKey now uses ResolveEncryptionKey (did_keys.go)
      which resolves by keyAgreement purpose. Falls back to WitnessKeys()[0].
    - FLAG 2 FIX: encodeCapsule has struct-layout-dependency comment.
OVERVIEW: AES-GCM and PRE publish paths with key store separation.
KEY DEPENDENCIES: ortholog-sdk/builder, crypto/artifact, lifecycle, storage, did
*/
package artifact

import (
	"encoding/base64"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	sdkartifact "github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) DelegationKeyStore — judicial-network-owned interface for PRE wrapped keys
// -------------------------------------------------------------------------------------------------

// DelegationKeyStore maps artifact CID to ECIES-wrapped PRE delegation keys.
// Separate from lifecycle.ArtifactKeyStore (fixed 44-byte struct).
// ECIES-wrapped delegation keys are ~113 bytes variable-length ciphertext.
type DelegationKeyStore interface {
	Store(cid storage.CID, wrappedKey []byte) error
	Get(cid storage.CID) ([]byte, error)
	Delete(cid storage.CID) error
}

// -------------------------------------------------------------------------------------------------
// 2) Types
// -------------------------------------------------------------------------------------------------

type PublishConfig struct {
	Plaintext         []byte
	SchemaRef         types.LogPosition
	OwnerDID          string
	Metadata          map[string]string
	DisclosureScope   string
	InitialRecipients []string
}

type PublishedArtifact struct {
	ArtifactCID       storage.CID
	ContentDigest     storage.CID
	Scheme            string
	Capsule           string
	CapsuleRaw        *sdkartifact.Capsule
	Metadata          map[string]string
	PkDel             string
	DisclosureScope   string
	InitialRecipients []string
}

// -------------------------------------------------------------------------------------------------
// 3) PublishArtifact
// -------------------------------------------------------------------------------------------------

func PublishArtifact(
	cfg PublishConfig,
	contentStore storage.ContentStore,
	keyStore lifecycle.ArtifactKeyStore,
	delKeyStore DelegationKeyStore,
	extractor schema.SchemaParameterExtractor,
	fetcher types.EntryFetcher,
	resolver did.DIDResolver,
) (*PublishedArtifact, error) {
	if len(cfg.Plaintext) == 0 {
		return nil, fmt.Errorf("artifact/publish: empty plaintext")
	}
	if contentStore == nil {
		return nil, fmt.Errorf("artifact/publish: nil content store")
	}

	contentDigest := storage.Compute(cfg.Plaintext)

	schemaParams, err := resolveSchemaParams(cfg.SchemaRef, extractor, fetcher)
	if err != nil {
		return nil, fmt.Errorf("artifact/publish: resolve schema: %w", err)
	}

	var result *PublishedArtifact
	switch schemaParams.ArtifactEncryption {
	case types.EncryptionAESGCM:
		if keyStore == nil {
			return nil, fmt.Errorf("artifact/publish: nil ArtifactKeyStore for AES-GCM")
		}
		result, err = publishAESGCM(cfg, contentStore, keyStore, contentDigest)
	case types.EncryptionUmbralPRE:
		if delKeyStore == nil {
			return nil, fmt.Errorf("artifact/publish: nil DelegationKeyStore for umbral_pre")
		}
		result, err = publishUmbralPRE(cfg, contentStore, delKeyStore, contentDigest, resolver)
	default:
		return nil, fmt.Errorf("artifact/publish: unknown encryption scheme %d", schemaParams.ArtifactEncryption)
	}
	if err != nil {
		return nil, err
	}

	result.Metadata = cfg.Metadata
	result.DisclosureScope = cfg.DisclosureScope
	result.InitialRecipients = cfg.InitialRecipients
	return result, nil
}

// -------------------------------------------------------------------------------------------------
// 4) AES-GCM publish path
// -------------------------------------------------------------------------------------------------

func publishAESGCM(
	cfg PublishConfig,
	contentStore storage.ContentStore,
	keyStore lifecycle.ArtifactKeyStore,
	contentDigest storage.CID,
) (*PublishedArtifact, error) {
	ciphertext, artKey, err := sdkartifact.EncryptArtifact(cfg.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("artifact/publish: encrypt aes_gcm: %w", err)
	}
	artifactCID := storage.Compute(ciphertext)
	if err := contentStore.Push(artifactCID, ciphertext); err != nil {
		return nil, fmt.Errorf("artifact/publish: push: %w", err)
	}
	if err := keyStore.Store(artifactCID, artKey); err != nil {
		return nil, fmt.Errorf("artifact/publish: store key: %w", err)
	}
	return &PublishedArtifact{
		ArtifactCID:   artifactCID,
		ContentDigest: contentDigest,
		Scheme:        "aes_gcm",
	}, nil
}

// -------------------------------------------------------------------------------------------------
// 5) Umbral PRE publish path
// -------------------------------------------------------------------------------------------------

func publishUmbralPRE(
	cfg PublishConfig,
	contentStore storage.ContentStore,
	delKeyStore DelegationKeyStore,
	contentDigest storage.CID,
	resolver did.DIDResolver,
) (*PublishedArtifact, error) {
	if resolver == nil {
		return nil, fmt.Errorf("artifact/publish: DIDResolver required for umbral_pre")
	}
	if cfg.OwnerDID == "" {
		return nil, fmt.Errorf("artifact/publish: OwnerDID required for umbral_pre")
	}

	// FLAG 1 FIX: Use ResolveEncryptionKey (keyAgreement purpose) instead of
	// WitnessKeys()[0]. Falls back to first available key for backward compat.
	ownerPK, err := ResolveEncryptionKey(cfg.OwnerDID, resolver)
	if err != nil {
		return nil, fmt.Errorf("artifact/publish: resolve owner pk: %w", err)
	}

	pkDel, wrappedSkDel, err := lifecycle.GenerateDelegationKey(ownerPK)
	if err != nil {
		return nil, fmt.Errorf("artifact/publish: generate delegation key: %w", err)
	}

	capsule, ciphertext, err := sdkartifact.PRE_Encrypt(pkDel, cfg.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("artifact/publish: pre_encrypt: %w", err)
	}

	artifactCID := storage.Compute(ciphertext)
	if err := contentStore.Push(artifactCID, ciphertext); err != nil {
		return nil, fmt.Errorf("artifact/publish: push: %w", err)
	}

	if err := delKeyStore.Store(artifactCID, wrappedSkDel); err != nil {
		return nil, fmt.Errorf("artifact/publish: store delegation key: %w", err)
	}

	capsuleB64 := encodeCapsule(capsule)
	pkDelB64 := base64.StdEncoding.EncodeToString(pkDel)

	return &PublishedArtifact{
		ArtifactCID:   artifactCID,
		ContentDigest: contentDigest,
		Scheme:        "umbral_pre",
		Capsule:       capsuleB64,
		CapsuleRaw:    capsule,
		PkDel:         pkDelB64,
	}, nil
}

// -------------------------------------------------------------------------------------------------
// 6) Helpers
// -------------------------------------------------------------------------------------------------

func resolveSchemaParams(
	schemaRef types.LogPosition,
	extractor schema.SchemaParameterExtractor,
	fetcher types.EntryFetcher,
) (*types.SchemaParameters, error) {
	if extractor == nil || schemaRef.IsNull() {
		return &types.SchemaParameters{
			ArtifactEncryption: types.EncryptionAESGCM,
		}, nil
	}
	meta, err := fetcher.Fetch(schemaRef)
	if err != nil || meta == nil {
		return nil, fmt.Errorf("schema entry not found at %s", schemaRef)
	}
	entry, err := deserializeEntry(meta.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("deserialize schema: %w", err)
	}
	params, err := extractor.Extract(entry)
	if err != nil {
		return nil, fmt.Errorf("extract params: %w", err)
	}
	return params, nil
}

// encodeCapsule serializes a Capsule to base64.
//
// FLAG 2 FIX — STRUCT LAYOUT DEPENDENCY:
// This function manually serializes Capsule{EX, EY, VX, VY, CheckVal}
// by extracting each field individually. If the SDK adds fields to
// sdkartifact.Capsule, this serialization will silently omit them.
//
// TODO: Switch to Capsule.Bytes() when the SDK provides a canonical
// serialization method. Until then, this manual approach is correct
// for the current Capsule struct layout (v1.3.2):
//   EX, EY *big.Int  — 32 bytes each (padded)
//   VX, VY *big.Int  — 32 bytes each (padded)
//   CheckVal [32]byte — 32 bytes
//   Total: 160 bytes → base64
func encodeCapsule(capsule *sdkartifact.Capsule) string {
	if capsule == nil {
		return ""
	}
	var buf []byte
	buf = append(buf, padBigInt(capsule.EX)...)
	buf = append(buf, padBigInt(capsule.EY)...)
	buf = append(buf, padBigInt(capsule.VX)...)
	buf = append(buf, padBigInt(capsule.VY)...)
	buf = append(buf, capsule.CheckVal[:]...)
	return base64.StdEncoding.EncodeToString(buf)
}

func padBigInt(b interface{ Bytes() []byte }) []byte {
	raw := b.Bytes()
	if len(raw) >= 32 {
		return raw[len(raw)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(raw):], raw)
	return padded
}

func deserializeEntry(data []byte) (*envelope.Entry, error) {
	return envelope.Deserialize(data)
}
