/*
FILE PATH:
    cases/artifact/publish.go

DESCRIPTION:
    Encrypts artifacts and pushes ciphertext to the content store. Dispatches
    between AES-256-GCM and Umbral PRE based on the schema's artifact_encryption
    field. Write-side entry point for all artifact operations.

KEY ARCHITECTURAL DECISIONS:
    - TWO KEY STORES, strict type separation:
      ArtifactKeyStore (SDK): stores artifact.ArtifactKey (Key[32]+Nonce[12]).
        Used by AES-GCM path only. 44-byte fixed struct.
      DelegationKeyStore (judicial-network): stores []byte ECIES ciphertext.
        Used by PRE path only. ~113 bytes variable. Domain-owned interface.
      The SDK's ArtifactKeyStore cannot hold wrapped delegation keys because
      artifact.ArtifactKey is a fixed 44-byte struct and ECIES output is ~113
      bytes. This is by design — the SDK documents that ArtifactKeyStore is
      "Not used by the PRE path."
    - PRE DELEGATION KEY PATTERN (MANDATORY per spec):
      Master identity key NEVER enters PRE operations. publish.go calls
      lifecycle.GenerateDelegationKey(ownerPubKey) → (pkDel, wrappedSkDel).
      PRE_Encrypt uses pkDel (NOT pk_owner). wrappedSkDel stored in
      DelegationKeyStore. Collusion extracts sk_del only. Zero lateral movement.

OVERVIEW:
    AES-GCM path:
      (1) content_digest = storage.Compute(plaintext)
      (2) ciphertext, artKey = EncryptArtifact(plaintext)
      (3) artifact_cid = storage.Compute(ciphertext)
      (4) contentStore.Push(artifact_cid, ciphertext)
      (5) keyStore.Store(artifact_cid, artKey)   ← ArtifactKeyStore (44-byte struct)

    PRE path:
      (1) content_digest = storage.Compute(plaintext)
      (2) pkDel, wrappedSkDel = lifecycle.GenerateDelegationKey(ownerPubKey)
      (3) capsule, ciphertext = PRE_Encrypt(pkDel, plaintext)
      (4) artifact_cid = storage.Compute(ciphertext)
      (5) contentStore.Push(artifact_cid, ciphertext)
      (6) delKeyStore.Store(artifact_cid, wrappedSkDel) ← DelegationKeyStore ([]byte)
      (7) Return: capsule, pkDel (base64) for Domain Payload

KEY DEPENDENCIES:
    - ortholog-sdk/builder: EntryFetcher for schema resolution
    - ortholog-sdk/crypto/artifact: EncryptArtifact, PRE_Encrypt, ArtifactKey
    - ortholog-sdk/lifecycle: ArtifactKeyStore (AES-GCM), GenerateDelegationKey (PRE)
    - ortholog-sdk/storage: ContentStore, CID computation
    - ortholog-sdk/did: DIDResolver for PRE owner public key resolution
*/
package artifact

import (
	"encoding/base64"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
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
// This is a domain concern — the SDK provides GenerateDelegationKey and
// UnwrapDelegationKey primitives; the judicial network stores the wrapped
// output however it wants.
//
// Separate from lifecycle.ArtifactKeyStore which stores artifact.ArtifactKey
// (fixed 44-byte struct for AES-GCM). ECIES-wrapped delegation keys are
// ~113 bytes of variable-length ciphertext and do not fit ArtifactKey.
//
// Production: backed by the same KMS/HSM infrastructure as ArtifactKeyStore.
// Testing: InMemoryDelegationKeyStore below.
type DelegationKeyStore interface {
	Store(cid storage.CID, wrappedKey []byte) error
	Get(cid storage.CID) ([]byte, error)
	Delete(cid storage.CID) error
}

// -------------------------------------------------------------------------------------------------
// 2) Types
// -------------------------------------------------------------------------------------------------

// PublishConfig configures a single artifact publish operation.
type PublishConfig struct {
	Plaintext         []byte
	SchemaRef         types.LogPosition
	OwnerDID          string
	Metadata          map[string]string
	DisclosureScope   string
	InitialRecipients []string
}

// PublishedArtifact is the result of a successful publish operation.
type PublishedArtifact struct {
	ArtifactCID       storage.CID
	ContentDigest     storage.CID
	Scheme            string
	Capsule           string
	CapsuleRaw        *sdkartifact.Capsule
	Metadata          map[string]string
	PkDel             string // base64 per-artifact delegation pubkey (PRE only)
	DisclosureScope   string
	InitialRecipients []string
}

// -------------------------------------------------------------------------------------------------
// 3) PublishArtifact
// -------------------------------------------------------------------------------------------------

// PublishArtifact encrypts plaintext, pushes ciphertext to the content store,
// and stores the encryption key material.
//
// AES-GCM artifacts store keys in keyStore (lifecycle.ArtifactKeyStore).
// PRE artifacts store wrapped delegation keys in delKeyStore (DelegationKeyStore).
// delKeyStore may be nil if the schema is known to be AES-GCM only.
func PublishArtifact(
	cfg PublishConfig,
	contentStore storage.ContentStore,
	keyStore lifecycle.ArtifactKeyStore,
	delKeyStore DelegationKeyStore,
	extractor schema.SchemaParameterExtractor,
	fetcher builder.EntryFetcher,
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
// 4) AES-GCM publish path — uses ArtifactKeyStore (44-byte struct)
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
// 5) Umbral PRE publish path — uses DelegationKeyStore ([]byte ECIES)
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

	ownerPK, err := resolvePublicKey(cfg.OwnerDID, resolver)
	if err != nil {
		return nil, fmt.Errorf("artifact/publish: resolve owner pk: %w", err)
	}

	// GenerateDelegationKey returns:
	//   pkDel:        65-byte uncompressed secp256k1 public key (ephemeral)
	//   wrappedSkDel: ~113 bytes ECIES ciphertext (sk_del wrapped for ownerPK)
	pkDel, wrappedSkDel, err := lifecycle.GenerateDelegationKey(ownerPK)
	if err != nil {
		return nil, fmt.Errorf("artifact/publish: generate delegation key: %w", err)
	}

	// PRE_Encrypt with pkDel — NOT pk_owner. Master key never enters PRE.
	capsule, ciphertext, err := sdkartifact.PRE_Encrypt(pkDel, cfg.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("artifact/publish: pre_encrypt: %w", err)
	}

	artifactCID := storage.Compute(ciphertext)
	if err := contentStore.Push(artifactCID, ciphertext); err != nil {
		return nil, fmt.Errorf("artifact/publish: push: %w", err)
	}

	// Store ECIES-wrapped delegation key in DelegationKeyStore ([]byte).
	// NOT in ArtifactKeyStore — ArtifactKey is a fixed 44-byte struct
	// and cannot hold ~113 bytes of ECIES ciphertext.
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
	fetcher builder.EntryFetcher,
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

func resolvePublicKey(didStr string, resolver did.DIDResolver) ([]byte, error) {
	doc, err := resolver.Resolve(didStr)
	if err != nil {
		return nil, err
	}
	keys, err := doc.WitnessKeys()
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no public keys in DID document %s", didStr)
	}
	return keys[0].PublicKey, nil
}

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
