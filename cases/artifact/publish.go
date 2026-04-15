/*
FILE PATH:
    cases/artifact/publish.go

DESCRIPTION:
    Encrypts artifacts and pushes ciphertext to the content store. Dispatches
    between AES-256-GCM and Umbral PRE based on the schema's artifact_encryption
    field. Write-side entry point for all artifact operations.

KEY ARCHITECTURAL DECISIONS:
    - Schema-driven dispatch: the encryption scheme comes from SchemaParameters,
      not from caller choice. The schema is the authority.
    - content_digest computed BEFORE encryption: storage.Compute(plaintext).
      Survives re-encryption (plaintext unchanged). artifact_cid computed
      AFTER encryption: storage.Compute(ciphertext). Changes on re-encryption.
    - PRE DELEGATION KEY PATTERN (MANDATORY per spec):
      Master identity key NEVER enters PRE operations. publish.go calls
      lifecycle.GenerateDelegationKey(ownerPubKey) → (pkDel, wrappedSkDel).
      PRE_Encrypt uses pkDel (NOT pk_owner). wrappedSkDel is stored in the
      ArtifactKeyStore. Collusion extracts sk_del (one artifact only).
      sk_owner is isolated. Zero lateral movement.
    - AES-GCM stores raw key material (Key[32]+Nonce[12]) in keyStore.
      PRE stores ECIES-wrapped delegation key in keyStore. Same interface.

OVERVIEW:
    AES-GCM path:
      (1) content_digest = storage.Compute(plaintext)
      (2) ciphertext, artKey = EncryptArtifact(plaintext)
      (3) artifact_cid = storage.Compute(ciphertext)
      (4) contentStore.Push(artifact_cid, ciphertext)
      (5) keyStore.Store(artifact_cid, artKey)

    PRE path:
      (1) content_digest = storage.Compute(plaintext)
      (2) pkDel, wrappedSkDel = lifecycle.GenerateDelegationKey(ownerPubKey)
      (3) capsule, ciphertext = PRE_Encrypt(pkDel, plaintext)  ← pkDel NOT pk_owner
      (4) artifact_cid = storage.Compute(ciphertext)
      (5) contentStore.Push(artifact_cid, ciphertext)
      (6) keyStore.Store(artifact_cid, wrappedSkDel)
      (7) Return: capsule, pkDel (base64), content_digest for Domain Payload

KEY DEPENDENCIES:
    - ortholog-sdk/builder: EntryFetcher for schema resolution
    - ortholog-sdk/crypto/artifact: EncryptArtifact, PRE_Encrypt
    - ortholog-sdk/lifecycle: ArtifactKeyStore, GenerateDelegationKey
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
// 1) Types
// -------------------------------------------------------------------------------------------------

// PublishConfig configures a single artifact publish operation.
type PublishConfig struct {
	// Plaintext is the raw artifact bytes (PDF, image, audio, etc.).
	Plaintext []byte

	// SchemaRef is the log position of the governing schema entry.
	SchemaRef types.LogPosition

	// OwnerDID is the artifact owner's DID. For Umbral PRE, this DID's
	// public key is resolved via DIDResolver. GenerateDelegationKey wraps
	// the delegation secret key under this public key via ECIES.
	OwnerDID string

	// Metadata is optional domain-specific metadata passed through.
	Metadata map[string]string

	// DisclosureScope controls who may receive access grants.
	DisclosureScope string

	// InitialRecipients are DIDs pre-authorized at filing time.
	InitialRecipients []string
}

// PublishedArtifact is the result of a successful publish operation.
type PublishedArtifact struct {
	ArtifactCID   storage.CID
	ContentDigest storage.CID
	Scheme        string
	Capsule       string
	CapsuleRaw    *sdkartifact.Capsule
	Metadata      map[string]string

	// PkDel is the base64-encoded per-artifact delegation public key.
	// Empty for AES-GCM. For PRE, this goes into the Domain Payload
	// and is read by retrieve.go as OwnerPubKey for GrantArtifactAccess.
	// This is NOT the owner's identity public key.
	PkDel string

	DisclosureScope   string
	InitialRecipients []string
}

// -------------------------------------------------------------------------------------------------
// 2) PublishArtifact
// -------------------------------------------------------------------------------------------------

// PublishArtifact encrypts plaintext, pushes ciphertext to the content
// store, and stores the encryption key. Returns a PublishedArtifact
// whose fields populate the entry's Domain Payload.
func PublishArtifact(
	cfg PublishConfig,
	contentStore storage.ContentStore,
	keyStore lifecycle.ArtifactKeyStore,
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
	if keyStore == nil {
		return nil, fmt.Errorf("artifact/publish: nil key store")
	}

	contentDigest := storage.Compute(cfg.Plaintext)

	schemaParams, err := resolveSchemaParams(cfg.SchemaRef, extractor, fetcher)
	if err != nil {
		return nil, fmt.Errorf("artifact/publish: resolve schema: %w", err)
	}

	var result *PublishedArtifact
	switch schemaParams.ArtifactEncryption {
	case types.EncryptionAESGCM:
		result, err = publishAESGCM(cfg, contentStore, keyStore, contentDigest)
	case types.EncryptionUmbralPRE:
		result, err = publishUmbralPRE(cfg, contentStore, keyStore, contentDigest, resolver)
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
// 3) AES-GCM publish path
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
// 4) Umbral PRE publish path — DELEGATION KEY PATTERN
// -------------------------------------------------------------------------------------------------

// publishUmbralPRE implements the mandatory delegation key pattern:
//
//	(1) Resolve owner's identity public key via DIDResolver
//	(2) GenerateDelegationKey(ownerPK) → pkDel (ephemeral), wrappedSkDel (ECIES)
//	(3) PRE_Encrypt(pkDel, plaintext) — pkDel, NOT pk_owner
//	(4) keyStore.Store(artifactCID, wrappedSkDel) — delegation key, not master
//	(5) Return pkDel (base64) for Domain Payload
//
// Security invariant: ownerPK is used ONLY as the ECIES wrapping target
// inside GenerateDelegationKey. It never enters PRE_Encrypt. If a grant
// is compromised, the attacker recovers sk_del (one artifact). sk_owner
// is isolated. Zero lateral movement.
func publishUmbralPRE(
	cfg PublishConfig,
	contentStore storage.ContentStore,
	keyStore lifecycle.ArtifactKeyStore,
	contentDigest storage.CID,
	resolver did.DIDResolver,
) (*PublishedArtifact, error) {
	if resolver == nil {
		return nil, fmt.Errorf("artifact/publish: DIDResolver required for umbral_pre")
	}
	if cfg.OwnerDID == "" {
		return nil, fmt.Errorf("artifact/publish: OwnerDID required for umbral_pre")
	}

	// (1) Resolve owner's identity public key.
	ownerPK, err := resolvePublicKey(cfg.OwnerDID, resolver)
	if err != nil {
		return nil, fmt.Errorf("artifact/publish: resolve owner pk: %w", err)
	}

	// (2) Generate per-artifact delegation keypair.
	// pkDel: ephemeral public key for PRE_Encrypt.
	// wrappedSkDel: ECIES-wrapped private key stored in keyStore.
	// ownerPK is the ECIES wrapping target only — never enters PRE.
	pkDel, wrappedSkDel, err := lifecycle.GenerateDelegationKey(ownerPK)
	if err != nil {
		return nil, fmt.Errorf("artifact/publish: generate delegation key: %w", err)
	}

	// (3) PRE_Encrypt with pkDel — NOT pk_owner.
	capsule, ciphertext, err := sdkartifact.PRE_Encrypt(pkDel, cfg.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("artifact/publish: pre_encrypt: %w", err)
	}

	// (4) Push ciphertext to content store.
	artifactCID := storage.Compute(ciphertext)
	if err := contentStore.Push(artifactCID, ciphertext); err != nil {
		return nil, fmt.Errorf("artifact/publish: push: %w", err)
	}

	// (5) Store wrapped delegation key (NOT raw key, NOT master key).
	// ArtifactKeyStore holds ECIES-wrapped sk_del. At grant time,
	// retrieve.go calls UnwrapDelegationKey(wrappedSkDel, ownerMasterSK)
	// to recover sk_del for KFrag generation.
	if err := keyStore.Store(artifactCID, wrappedSkDel); err != nil {
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
// 5) Helpers
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
