/*
FILE PATH:

	cases/artifact/retrieve.go

DESCRIPTION:

	Performs sealing checks, resolves authorized recipients from disclosure
	orders, and delegates to the SDK's GrantArtifactAccess for artifact
	retrieval. This is the judicial network's authorization policy adapter.

KEY ARCHITECTURAL DECISIONS:
  - TWO KEY STORES: ArtifactKeyStore (AES-GCM, passed to SDK via params.KeyStore)
    and DelegationKeyStore (PRE wrapped keys, read by judicial-network code).
    The SDK never sees wrapped delegation keys or the master identity key.
  - PRE UNWRAP OUTSIDE SDK: retrieve.go calls delKeyStore.Get → lifecycle.UnwrapDelegationKey
    → passes unwrapped sk_del as OwnerSecretKey. The SDK receives a 32-byte
    scalar and calls PRE_GenerateKFrags with it. In production, the HSM
    performs ECIES_Decrypt internally and never exports the master key.
  - GrantArtifactAccessParams.OwnerSecretKey receives sk_del (per-artifact
    delegation key), NOT the master identity key. This field name is locked
    in the SDK. The judicial network is responsible for the unwrap step.

OVERVIEW:

	(1) Validate request
	(2) Sealing check → ErrSealed
	(3) Resolve authorized recipients from filing + disclosure orders
	(4) PRE path: delKeyStore.Get(cid) → UnwrapDelegationKey(wrapped, masterKey) → skDel
	(5) Pass skDel as OwnerSecretKey + Capsule to GrantArtifactAccess
	    (pk_del is NOT a grant input — it belongs on the decrypt path)
	(6) Return GrantArtifactAccessResult

KEY DEPENDENCIES:
  - ortholog-sdk/builder: EntryFetcher
  - ortholog-sdk/lifecycle: GrantArtifactAccess, UnwrapDelegationKey, ArtifactKeyStore
  - ortholog-sdk/core/smt: LeafReader for sealing check + authority chain
  - judicial-network/schemas: disclosure order payload extraction
  - DelegationKeyStore (defined in publish.go, same package)
*/
package artifact

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	sdkartifact "github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// -------------------------------------------------------------------------------------------------
// 1) Errors
// -------------------------------------------------------------------------------------------------

var ErrSealed = errors.New("artifact/retrieve: document is sealed")
var ErrExpunged = errors.New("artifact/retrieve: document has been expunged")
var ErrNotFound = errors.New("artifact/retrieve: artifact not found")
var ErrUnauthorized = errors.New("artifact/retrieve: requester not authorized")

// -------------------------------------------------------------------------------------------------
// 2) Types
// -------------------------------------------------------------------------------------------------

// RetrievalRequest configures an artifact retrieval operation.
type RetrievalRequest struct {
	ArtifactCID     storage.CID
	ContentDigest   storage.CID
	FilingEntryPos  types.LogPosition
	CaseRootPos     types.LogPosition
	ScopePos        types.LogPosition
	RequesterPubKey []byte
	RequesterDID    string
	GranterDID      string
	SchemaRef       types.LogPosition
	RetrievalExpiry time.Duration

	// ── PRE fields (evidence artifacts) ──────────────────────────────

	// OwnerMasterKey is the owner's master identity secret key (32 bytes).
	// Used ONLY for ECIES unwrapping of the per-artifact delegation key.
	// NEVER passed to GrantArtifactAccess. In production: HSM performs
	// ECIES_Decrypt internally and this field is not needed — the HSM
	// returns sk_del directly.
	OwnerMasterKey []byte

	// PkDel is the per-artifact delegation public key (65 bytes) from the
	// filing entry's Domain Payload. NOT an input to GrantArtifactAccess
	// (KFrag generation needs only sk_del + recipient pubkey). Carried on
	// the request for downstream use: the free tier proxy passes it as
	// OwnerPubKey to VerifyAndDecryptArtifact (PRE_DecryptFrags needs it).
	PkDel []byte

	// Capsule from the filing entry's Domain Payload.
	Capsule *sdkartifact.Capsule
}

// -------------------------------------------------------------------------------------------------
// 3) RetrieveArtifact
// -------------------------------------------------------------------------------------------------

// RetrieveArtifact performs sealing check, resolves authorized recipients,
// unwraps the PRE delegation key if needed, and delegates to SDK
// GrantArtifactAccess.
//
// keyStore: AES-GCM key material (passed to SDK via params.KeyStore).
// delKeyStore: PRE wrapped delegation keys (read by this function, not by SDK).
// delKeyStore may be nil if the schema is known to be AES-GCM only.
func RetrieveArtifact(
	req RetrievalRequest,
	keyStore lifecycle.ArtifactKeyStore,
	delKeyStore DelegationKeyStore,
	retrievalProvider storage.RetrievalProvider,
	extractor schema.SchemaParameterExtractor,
	leafReader smt.LeafReader,
	fetcher builder.EntryFetcher,
	resolver did.DIDResolver,
) (*lifecycle.GrantArtifactAccessResult, error) {
	if req.ArtifactCID.IsZero() {
		return nil, ErrNotFound
	}

	// (2) Sealing check.
	sealed, err := checkSealed(req.CaseRootPos, leafReader)
	if err != nil {
		return nil, fmt.Errorf("artifact/retrieve: sealing check: %w", err)
	}
	if sealed {
		return nil, ErrSealed
	}

	// (3) Resolve schema parameters.
	schemaParams, err := resolveSchemaParams(req.SchemaRef, extractor, fetcher)
	if err != nil {
		schemaParams = &types.SchemaParameters{
			ArtifactEncryption: types.EncryptionAESGCM,
		}
	}

	// (4) Resolve authorized recipients.
	authorizedRecipients, err := resolveAuthorizedRecipients(
		req.FilingEntryPos, req.CaseRootPos, req.ArtifactCID,
		fetcher, leafReader,
	)
	if err != nil {
		authorizedRecipients = nil
	}

	// (5) Build grant params.
	expiry := req.RetrievalExpiry
	if expiry <= 0 {
		expiry = 1 * time.Hour
	}

	var scopePtr *types.LogPosition
	if !req.ScopePos.IsNull() {
		scopePtr = &req.ScopePos
	}

	grantParams := lifecycle.GrantArtifactAccessParams{
		ArtifactCID:          req.ArtifactCID,
		ContentDigest:        req.ContentDigest,
		RecipientPubKey:      req.RequesterPubKey,
		KeyStore:             keyStore,
		RetrievalProvider:    retrievalProvider,
		RetrievalExpiry:      expiry,
		SchemaParams:         schemaParams,
		GranterDID:           req.GranterDID,
		RecipientDID:         req.RequesterDID,
		AuthorizedRecipients: authorizedRecipients,
		ScopePointer:         scopePtr,
		LeafReader:           leafReader,
		Fetcher:              fetcher,
	}

	// (6) PRE path: unwrap delegation key OUTSIDE the SDK.
	// The SDK receives the unwrapped 32-byte sk_del via OwnerSecretKey.
	// The SDK never sees the wrapped key or the master key.
	if schemaParams.ArtifactEncryption == types.EncryptionUmbralPRE {
		if delKeyStore == nil {
			return nil, fmt.Errorf("artifact/retrieve: nil DelegationKeyStore for umbral_pre")
		}

		// Fetch ECIES-wrapped delegation key from judicial-network store.
		wrappedSkDel, err := delKeyStore.Get(req.ArtifactCID)
		if err != nil {
			return nil, fmt.Errorf("artifact/retrieve: fetch delegation key: %w", err)
		}
		if wrappedSkDel == nil {
			return nil, ErrExpunged
		}

		// Unwrap: ECIES-decrypt with owner's master key → sk_del.
		// In production: skDel = hsm.ECIESDecrypt(wrappedSkDel)
		// The master key never reaches the SDK.
		skDel, err := lifecycle.UnwrapDelegationKey(wrappedSkDel, req.OwnerMasterKey)
		if err != nil {
			return nil, fmt.Errorf("artifact/retrieve: unwrap delegation key: %w", err)
		}

		// Pass unwrapped delegation key to SDK — SDK doesn't know the difference
		// between sk_del and any other 32-byte scalar.
		// GrantArtifactAccessParams has OwnerSecretKey + Capsule only.
		// pk_del is NOT an input to KFrag generation — it belongs on the
		// decrypt path (VerifyAndDecryptArtifactParams.OwnerPubKey) where
		// the recipient calls PRE_DecryptFrags. Stored on the request for
		// callers who need it downstream (e.g., free tier proxy mode).
		grantParams.OwnerSecretKey = skDel // per-artifact delegation key
		grantParams.Capsule = req.Capsule
	}

	result, err := lifecycle.GrantArtifactAccess(grantParams)
	if err != nil {
		if isAuthorizationError(err) {
			return nil, ErrUnauthorized
		}
		if isKeyNotFoundError(err) {
			return nil, ErrExpunged
		}
		return nil, fmt.Errorf("artifact/retrieve: grant: %w", err)
	}

	return result, nil
}

// -------------------------------------------------------------------------------------------------
// 4) Sealing check
// -------------------------------------------------------------------------------------------------

func checkSealed(caseRootPos types.LogPosition, leafReader smt.LeafReader) (bool, error) {
	if caseRootPos.IsNull() {
		return false, nil
	}
	key := smt.DeriveKey(caseRootPos)
	leaf, err := leafReader.Get(key)
	if err != nil {
		return false, fmt.Errorf("read leaf: %w", err)
	}
	if leaf == nil {
		return false, nil
	}
	if !leaf.AuthorityTip.Equal(caseRootPos) && !leaf.AuthorityTip.Equal(leaf.OriginTip) {
		return true, nil
	}
	return false, nil
}

// -------------------------------------------------------------------------------------------------
// 5) Authorized recipients resolution
// -------------------------------------------------------------------------------------------------

func resolveAuthorizedRecipients(
	filingPos types.LogPosition,
	caseRootPos types.LogPosition,
	artifactCID storage.CID,
	fetcher builder.EntryFetcher,
	leafReader smt.LeafReader,
) ([]string, error) {
	recipients := make(map[string]bool)

	if !filingPos.IsNull() {
		filingMeta, err := fetcher.Fetch(filingPos)
		if err == nil && filingMeta != nil {
			initial := extractInitialRecipients(filingMeta.CanonicalBytes)
			for _, d := range initial {
				recipients[d] = true
			}
		}
	}

	if !caseRootPos.IsNull() {
		disclosureRecipients := scanDisclosureOrders(
			caseRootPos, artifactCID.String(), fetcher, leafReader,
		)
		for _, d := range disclosureRecipients {
			recipients[d] = true
		}
	}

	if len(recipients) == 0 {
		return nil, nil
	}
	result := make([]string, 0, len(recipients))
	for d := range recipients {
		result = append(result, d)
	}
	return result, nil
}

func extractInitialRecipients(canonicalBytes []byte) []string {
	entry, err := deserializeEntry(canonicalBytes)
	if err != nil || entry == nil {
		return nil
	}
	if len(entry.DomainPayload) == 0 {
		return nil
	}
	var payload struct {
		AuthorizedRecipients []string `json:"authorized_recipients"`
	}
	if err := json.Unmarshal(entry.DomainPayload, &payload); err != nil {
		return nil
	}
	return payload.AuthorizedRecipients
}

// -------------------------------------------------------------------------------------------------
// 6) Disclosure order scanning
// -------------------------------------------------------------------------------------------------

const maxAuthorityChainScan = 200

func scanDisclosureOrders(
	caseRootPos types.LogPosition,
	artifactCIDStr string,
	fetcher builder.EntryFetcher,
	leafReader smt.LeafReader,
) []string {
	key := smt.DeriveKey(caseRootPos)
	leaf, err := leafReader.Get(key)
	if err != nil || leaf == nil {
		return nil
	}
	if leaf.AuthorityTip.Equal(caseRootPos) {
		return nil
	}

	var allRecipients []string
	current := leaf.AuthorityTip
	visited := make(map[types.LogPosition]bool)

	for depth := 0; depth < maxAuthorityChainScan; depth++ {
		if visited[current] || current.Equal(caseRootPos) {
			break
		}
		visited[current] = true

		meta, fetchErr := fetcher.Fetch(current)
		if fetchErr != nil || meta == nil {
			break
		}
		entry, desErr := deserializeEntry(meta.CanonicalBytes)
		if desErr != nil || entry == nil {
			break
		}
		if len(entry.DomainPayload) > 0 {
			if schemas.DisclosureOrderAppliesToArtifact(entry.DomainPayload, artifactCIDStr) {
				recipients, _ := schemas.ExtractDisclosureRecipients(entry.DomainPayload)
				allRecipients = append(allRecipients, recipients...)
			}
		}
		if entry.Header.PriorAuthority == nil {
			break
		}
		current = *entry.Header.PriorAuthority
	}

	return allRecipients
}

// -------------------------------------------------------------------------------------------------
// 7) Error classification
// -------------------------------------------------------------------------------------------------

func isAuthorizationError(err error) bool {
	if err == nil {
		return false
	}
	return containsStr(err.Error(), "grant denied")
}

func isKeyNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, storage.ErrContentNotFound) ||
		containsStr(err.Error(), "key not found")
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
