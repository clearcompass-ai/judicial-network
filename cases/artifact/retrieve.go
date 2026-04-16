/*
FILE PATH: cases/artifact/retrieve.go
DESCRIPTION: Sealing checks, authorized recipients, SDK GrantArtifactAccess.
KEY ARCHITECTURAL DECISIONS:
    - DRIFT 1 FIX: Uses verifier.EvaluateOrigin for entity state check
      (handles path compression, revocation, succession). Manual AuthorityTip
      check retained for sealing detection (authority-lane concern).
    - TWO KEY STORES: ArtifactKeyStore (AES-GCM) and DelegationKeyStore (PRE).
    - PRE UNWRAP OUTSIDE SDK: delKeyStore.Get → UnwrapDelegationKey → sk_del.
    - GrantArtifactAccessParams.OwnerSecretKey receives sk_del, NOT master key.
OVERVIEW: RetrieveArtifact → entity state check → sealing check →
    authorized recipients → GrantArtifactAccess.
KEY DEPENDENCIES: ortholog-sdk/builder, lifecycle, smt, verifier, judicial-network/schemas
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
	"github.com/clearcompass-ai/ortholog-sdk/verifier"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

var ErrSealed = errors.New("artifact/retrieve: document is sealed")
var ErrExpunged = errors.New("artifact/retrieve: document has been expunged")
var ErrNotFound = errors.New("artifact/retrieve: artifact not found")
var ErrUnauthorized = errors.New("artifact/retrieve: requester not authorized")
var ErrCaseRevoked = errors.New("artifact/retrieve: case entity revoked or succeeded")

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
	OwnerMasterKey  []byte
	// PkDel: per-artifact delegation public key. NOT a grant input.
	// Carried for downstream decrypt path (VerifyAndDecryptArtifact.OwnerPubKey).
	PkDel   []byte
	Capsule *sdkartifact.Capsule
}

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

	// DRIFT 1 FIX: Use SDK verifier.EvaluateOrigin for entity state check.
	// Handles path compression (TargetIntermediate), revocation, succession.
	// Then check authority lane for sealing (enforcement-specific).
	blocked, err := checkEntityAccess(req.CaseRootPos, leafReader, fetcher)
	if err != nil {
		return nil, fmt.Errorf("artifact/retrieve: access check: %w", err)
	}
	if blocked != nil {
		return nil, blocked
	}

	schemaParams, err := resolveSchemaParams(req.SchemaRef, extractor, fetcher)
	if err != nil {
		schemaParams = &types.SchemaParameters{ArtifactEncryption: types.EncryptionAESGCM}
	}

	authorizedRecipients, err := resolveAuthorizedRecipients(
		req.FilingEntryPos, req.CaseRootPos, req.ArtifactCID, fetcher, leafReader,
	)
	if err != nil {
		authorizedRecipients = nil
	}

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

	if schemaParams.ArtifactEncryption == types.EncryptionUmbralPRE {
		if delKeyStore == nil {
			return nil, fmt.Errorf("artifact/retrieve: nil DelegationKeyStore for umbral_pre")
		}
		wrappedSkDel, dErr := delKeyStore.Get(req.ArtifactCID)
		if dErr != nil {
			return nil, fmt.Errorf("artifact/retrieve: fetch delegation key: %w", dErr)
		}
		if wrappedSkDel == nil {
			return nil, ErrExpunged
		}
		skDel, uErr := lifecycle.UnwrapDelegationKey(wrappedSkDel, req.OwnerMasterKey)
		if uErr != nil {
			return nil, fmt.Errorf("artifact/retrieve: unwrap delegation key: %w", uErr)
		}
		grantParams.OwnerSecretKey = skDel
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
// Entity access check (Drift 1 fix: SDK verifier.EvaluateOrigin + authority lane)
// -------------------------------------------------------------------------------------------------

// checkEntityAccess uses SDK verifier.EvaluateOrigin to check entity state
// (handles path compression, revocation, succession that raw leaf reads miss),
// then checks the authority lane for sealing enforcement entries.
// Returns nil if access is allowed, or a typed error if blocked.
func checkEntityAccess(
	caseRootPos types.LogPosition,
	leafReader smt.LeafReader,
	fetcher builder.EntryFetcher,
) (error, error) {
	if caseRootPos.IsNull() {
		return nil, nil
	}

	leafKey := smt.DeriveKey(caseRootPos)

	// Step 1: SDK origin evaluation — catches revocation, succession, and
	// path compression that raw AuthorityTip comparisons miss.
	eval, err := verifier.EvaluateOrigin(leafKey, leafReader, fetcher)
	if err != nil {
		// Entity not found is not an error — case may not exist yet.
		if errors.Is(err, verifier.ErrLeafNotFound) {
			return nil, nil
		}
		return nil, err
	}

	switch eval.State {
	case verifier.OriginRevoked:
		return ErrCaseRevoked, nil
	case verifier.OriginSucceeded:
		return ErrCaseRevoked, nil
	}

	// Step 2: Authority lane check — sealing is an enforcement concern.
	// AuthorityTip diverged from both self AND OriginTip = enforcement active.
	leaf, err := leafReader.Get(leafKey)
	if err != nil || leaf == nil {
		return nil, nil
	}
	if !leaf.AuthorityTip.Equal(caseRootPos) && !leaf.AuthorityTip.Equal(leaf.OriginTip) {
		return ErrSealed, nil
	}

	return nil, nil
}

// -------------------------------------------------------------------------------------------------
// Authorized recipients resolution
// -------------------------------------------------------------------------------------------------

func resolveAuthorizedRecipients(
	filingPos, caseRootPos types.LogPosition, artifactCID storage.CID,
	fetcher builder.EntryFetcher, leafReader smt.LeafReader,
) ([]string, error) {
	recipients := make(map[string]bool)
	if !filingPos.IsNull() {
		filingMeta, err := fetcher.Fetch(filingPos)
		if err == nil && filingMeta != nil {
			for _, d := range extractInitialRecipients(filingMeta.CanonicalBytes) {
				recipients[d] = true
			}
		}
	}
	if !caseRootPos.IsNull() {
		for _, d := range scanDisclosureOrders(caseRootPos, artifactCID.String(), fetcher, leafReader) {
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
	if err != nil || entry == nil || len(entry.DomainPayload) == 0 {
		return nil
	}
	var payload struct {
		AuthorizedRecipients []string `json:"authorized_recipients"`
	}
	if json.Unmarshal(entry.DomainPayload, &payload) != nil {
		return nil
	}
	return payload.AuthorizedRecipients
}

// -------------------------------------------------------------------------------------------------
// Disclosure order scanning
// -------------------------------------------------------------------------------------------------

const maxAuthorityChainScan = 200

func scanDisclosureOrders(
	caseRootPos types.LogPosition, artifactCIDStr string,
	fetcher builder.EntryFetcher, leafReader smt.LeafReader,
) []string {
	key := smt.DeriveKey(caseRootPos)
	leaf, err := leafReader.Get(key)
	if err != nil || leaf == nil || leaf.AuthorityTip.Equal(caseRootPos) {
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
		meta, fErr := fetcher.Fetch(current)
		if fErr != nil || meta == nil {
			break
		}
		entry, dErr := deserializeEntry(meta.CanonicalBytes)
		if dErr != nil || entry == nil {
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
// Error classification
// -------------------------------------------------------------------------------------------------

func isAuthorizationError(err error) bool {
	return err != nil && containsStr(err.Error(), "grant denied")
}

func isKeyNotFoundError(err error) bool {
	return err != nil && (errors.Is(err, storage.ErrContentNotFound) || containsStr(err.Error(), "key not found"))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
