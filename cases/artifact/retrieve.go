/*
FILE PATH:
    cases/artifact/retrieve.go

DESCRIPTION:
    Performs sealing checks, resolves authorized recipients from disclosure
    orders, and delegates to the SDK's GrantArtifactAccess for artifact
    retrieval. This file is the judicial network's authorization policy
    adapter — it does the ONE thing the SDK cannot: read disclosure order
    Domain Payloads to extract the authorized recipients list.

KEY ARCHITECTURAL DECISIONS:
    - No local interface redefinitions. Uses builder.EntryFetcher directly.
    - PRE DELEGATION KEY UNWRAP (MANDATORY per spec):
      retrieve.go fetches the ECIES-wrapped delegation key from keyStore,
      calls lifecycle.UnwrapDelegationKey(wrappedKey, ownerMasterKey) to
      recover sk_del, then passes sk_del (NOT the master key) as
      OwnerSecretKey to GrantArtifactAccess. OwnerPubKey is pk_del from
      the Domain Payload — NOT pk_owner.
    - Error classification via SDK error message: checks for the stable
      prefix "grant denied" in the SDK's error format.
    - Disclosure order scanning walks the authority chain backward from
      AuthorityTip, collecting recipients from all matching orders.

OVERVIEW:
    (1) Validate request
    (2) Sealing check: read Authority_Tip → if sealed, return ErrSealed
    (3) Resolve authorization:
        a. Read filing entry Domain Payload → initial authorized_recipients
        b. Scan authority chain for disclosure orders targeting this artifact
        c. Merge recipients from filing + all matching disclosure orders
    (4) For PRE schemas: keyStore.Get(cid) → UnwrapDelegationKey → sk_del
    (5) Pass merged AuthorizedRecipients + sk_del to SDK GrantArtifactAccess
    (6) Return GrantArtifactAccessResult to caller

KEY DEPENDENCIES:
    - ortholog-sdk/builder: EntryFetcher (canonical interface, no local copy)
    - ortholog-sdk/lifecycle: GrantArtifactAccess, UnwrapDelegationKey, ArtifactKeyStore
    - ortholog-sdk/core/smt: LeafReader for sealing check + authority chain
    - judicial-network/schemas: ExtractDisclosureRecipients, DisclosureOrderAppliesToArtifact
*/
package artifact

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	sdkartifact "github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
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

	// OwnerMasterKey is the artifact owner's master identity secret key
	// (32-byte secp256k1 scalar). Used ONLY for ECIES unwrapping of the
	// per-artifact delegation key via lifecycle.UnwrapDelegationKey.
	// NEVER passed directly as OwnerSecretKey to GrantArtifactAccess.
	// In production: HSM performs ECIES_Decrypt internally.
	OwnerMasterKey []byte

	// PkDel is the per-artifact delegation public key (65-byte uncompressed
	// secp256k1) from the filing entry's Domain Payload. This is the key
	// that was used for PRE_Encrypt at publish time. Passed as OwnerPubKey
	// to GrantArtifactAccess. NOT pk_owner.
	PkDel []byte

	// Capsule is the Umbral PRE capsule from the filing entry's Domain Payload.
	Capsule *sdkartifact.Capsule
}

// -------------------------------------------------------------------------------------------------
// 3) RetrieveArtifact
// -------------------------------------------------------------------------------------------------

// RetrieveArtifact performs sealing check, resolves authorized recipients,
// unwraps the PRE delegation key if needed, and delegates to SDK
// GrantArtifactAccess.
func RetrieveArtifact(
	req RetrievalRequest,
	keyStore lifecycle.ArtifactKeyStore,
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

	// (4) Resolve authorized recipients from filing entry + disclosure orders.
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

	// (6) PRE-specific: unwrap delegation key from keyStore.
	// The keyStore holds ECIES-wrapped sk_del (stored by publish.go).
	// UnwrapDelegationKey recovers sk_del using the owner's master key.
	// sk_del is passed as OwnerSecretKey. pk_del is passed as OwnerPubKey.
	// The master key NEVER reaches GrantArtifactAccess.
	if schemaParams.ArtifactEncryption == types.EncryptionUmbralPRE {
		if keyStore == nil {
			return nil, ErrExpunged
		}

		// Fetch the wrapped delegation key from the key store.
		wrappedKey, err := keyStore.Get(req.ArtifactCID)
		if err != nil {
			if isKeyNotFoundError(err) {
				return nil, ErrExpunged
			}
			return nil, fmt.Errorf("artifact/retrieve: fetch delegation key: %w", err)
		}

		// Unwrap: ECIES-decrypt with owner's master key → sk_del.
		// In production the master key lives in an HSM and
		// UnwrapDelegationKey calls HSM.ECIES_Decrypt internally.
		skDel, err := lifecycle.UnwrapDelegationKey(wrappedKey, req.OwnerMasterKey)
		if err != nil {
			return nil, fmt.Errorf("artifact/retrieve: unwrap delegation key: %w", err)
		}

		grantParams.OwnerSecretKey = skDel    // per-artifact delegation key
		grantParams.OwnerPubKey = req.PkDel   // per-artifact delegation public key
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
// 4) Sealing check — O(1), one leaf read
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
// 5) Authorized recipients resolution — domain-specific payload reading
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
// 6) Disclosure order scanning — authority chain walk
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
// 7) Error classification helpers
// -------------------------------------------------------------------------------------------------

// isAuthorizationError checks if the SDK returned a grant authorization
// failure. The SDK wraps denial as:
//
//	fmt.Errorf("lifecycle/artifact: grant denied: %s", check.Reason)
//
// The stable prefix "grant denied" is the reliable indicator.
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
