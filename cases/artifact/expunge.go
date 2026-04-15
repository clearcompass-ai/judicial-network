/*
FILE PATH:
    cases/artifact/expunge.go

DESCRIPTION:
    Destroys artifact keys and performs backend cleanup for cryptographic
    erasure. Key destruction is THE cryptographic guarantee.

KEY ARCHITECTURAL DECISIONS:
    - AES-GCM: keyStore.Delete destroys the 44-byte ArtifactKey.
    - PRE: delKeyStore.Delete destroys the wrapped delegation key.
      Without the wrapped key, no one can call UnwrapDelegationKey,
      so no new KFrags/CFrags can be produced. Existing CFrags become
      useless without M valid fragments for a new capsule.
    - Both deletions are attempted. Either alone is sufficient for
      cryptographic erasure of the respective path.
    - Content store deletion is defense-in-depth (IPFS returns 501).

OVERVIEW:
    ExpungeArtifact: keyStore.Delete + delKeyStore.Delete + contentStore.Delete.
    BatchExpunge: multiple CIDs, continues on individual failures.

KEY DEPENDENCIES:
    - ortholog-sdk/lifecycle: ArtifactKeyStore for AES-GCM key destruction
    - ortholog-sdk/storage: ContentStore for ciphertext removal
    - DelegationKeyStore (defined in publish.go) for PRE key destruction
*/
package artifact

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// -------------------------------------------------------------------------------------------------
// 1) Types
// -------------------------------------------------------------------------------------------------

// ExpungeConfig configures an artifact expungement operation.
type ExpungeConfig struct {
	ArtifactCID        storage.CID
	VerifyBeforeDelete bool
}

// ExpungeResult holds the outcome of an expungement operation.
type ExpungeResult struct {
	AESKeyDestroyed        bool
	DelegationKeyDestroyed bool
	ContentDeleted         bool
	ContentDeleteError     error
}

// -------------------------------------------------------------------------------------------------
// 2) ExpungeArtifact
// -------------------------------------------------------------------------------------------------

// ExpungeArtifact performs cryptographic erasure of an artifact.
// Destroys key material from BOTH stores (AES-GCM and PRE delegation).
// Either store may be nil if the artifact type is known.
// At least one key store must be non-nil.
func ExpungeArtifact(
	cfg ExpungeConfig,
	keyStore lifecycle.ArtifactKeyStore,
	delKeyStore DelegationKeyStore,
	contentStore storage.ContentStore,
) (*ExpungeResult, error) {
	if cfg.ArtifactCID.IsZero() {
		return nil, fmt.Errorf("artifact/expunge: zero artifact CID")
	}
	if keyStore == nil && delKeyStore == nil {
		return nil, fmt.Errorf("artifact/expunge: both key stores are nil")
	}

	result := &ExpungeResult{}

	if cfg.VerifyBeforeDelete && contentStore != nil {
		_, err := contentStore.Exists(cfg.ArtifactCID)
		if err != nil {
			return nil, fmt.Errorf("artifact/expunge: verify existence: %w", err)
		}
	}

	// Destroy AES-GCM key (if store provided).
	if keyStore != nil {
		if err := keyStore.Delete(cfg.ArtifactCID); err == nil {
			result.AESKeyDestroyed = true
		}
		// Non-fatal: key may not exist if this is a PRE-only artifact.
	}

	// Destroy PRE wrapped delegation key (if store provided).
	if delKeyStore != nil {
		if err := delKeyStore.Delete(cfg.ArtifactCID); err == nil {
			result.DelegationKeyDestroyed = true
		}
		// Non-fatal: key may not exist if this is an AES-GCM-only artifact.
	}

	if !result.AESKeyDestroyed && !result.DelegationKeyDestroyed {
		return nil, fmt.Errorf("artifact/expunge: no key material destroyed for %s", cfg.ArtifactCID)
	}

	// Defense-in-depth: delete ciphertext from content store.
	if contentStore != nil {
		err := contentStore.Delete(cfg.ArtifactCID)
		if err != nil {
			result.ContentDeleteError = err
		} else {
			result.ContentDeleted = true
		}
	}

	return result, nil
}

// -------------------------------------------------------------------------------------------------
// 3) BatchExpunge
// -------------------------------------------------------------------------------------------------

// BatchExpungeResult holds the outcome of a batch expungement.
type BatchExpungeResult struct {
	Total          int
	KeysDestroyed  int
	ContentDeleted int
	Errors         map[string]error
}

// BatchExpunge expunges multiple artifacts. Continues on individual failures.
func BatchExpunge(
	cids []storage.CID,
	keyStore lifecycle.ArtifactKeyStore,
	delKeyStore DelegationKeyStore,
	contentStore storage.ContentStore,
) (*BatchExpungeResult, error) {
	if keyStore == nil && delKeyStore == nil {
		return nil, fmt.Errorf("artifact/expunge: both key stores are nil")
	}

	result := &BatchExpungeResult{
		Total:  len(cids),
		Errors: make(map[string]error),
	}

	for _, cid := range cids {
		expResult, err := ExpungeArtifact(
			ExpungeConfig{ArtifactCID: cid},
			keyStore, delKeyStore, contentStore,
		)
		if err != nil {
			result.Errors[cid.String()] = err
			continue
		}
		if expResult.AESKeyDestroyed || expResult.DelegationKeyDestroyed {
			result.KeysDestroyed++
		}
		if expResult.ContentDeleted {
			result.ContentDeleted++
		}
	}

	return result, nil
}
