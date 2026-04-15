/*
FILE PATH:
    cases/artifact/expunge.go

DESCRIPTION:
    Destroys artifact keys and performs backend cleanup for cryptographic
    erasure. Key destruction is THE cryptographic guarantee — after deletion,
    ciphertext is computationally irrecoverable regardless of CAS state.

KEY ARCHITECTURAL DECISIONS:
    - Key destruction is step 1, content deletion is step 2 (defense-in-depth).
      Step 1 alone is sufficient for NIST SP 800-88 compliance.
    - IPFS returns ErrNotSupported for Delete (best-effort GC). This is
      expected and documented. The function succeeds if step 1 succeeds.
    - For Umbral PRE: wrapped delegation key destroyed → KFrags useless → no new CFrags.
    - Control Header on log remains (proves record existed). CID points nowhere.

OVERVIEW:
    ExpungeArtifact: keyStore.Delete(cid) → contentStore.Delete(cid).
    BatchExpunge: multiple CIDs, continues on individual failures.

KEY DEPENDENCIES:
    - ortholog-sdk/lifecycle: ArtifactKeyStore for key destruction
    - ortholog-sdk/storage: ContentStore for ciphertext removal
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
	KeyDestroyed       bool
	ContentDeleted     bool
	ContentDeleteError error
}

// -------------------------------------------------------------------------------------------------
// 2) ExpungeArtifact
// -------------------------------------------------------------------------------------------------

// ExpungeArtifact performs cryptographic erasure of an artifact.
func ExpungeArtifact(
	cfg ExpungeConfig,
	keyStore lifecycle.ArtifactKeyStore,
	contentStore storage.ContentStore,
) (*ExpungeResult, error) {
	if cfg.ArtifactCID.IsZero() {
		return nil, fmt.Errorf("artifact/expunge: zero artifact CID")
	}
	if keyStore == nil {
		return nil, fmt.Errorf("artifact/expunge: nil key store")
	}

	result := &ExpungeResult{}

	if cfg.VerifyBeforeDelete && contentStore != nil {
		_, err := contentStore.Exists(cfg.ArtifactCID)
		if err != nil {
			return nil, fmt.Errorf("artifact/expunge: verify existence: %w", err)
		}
	}

	if err := keyStore.Delete(cfg.ArtifactCID); err != nil {
		return nil, fmt.Errorf("artifact/expunge: destroy key: %w", err)
	}
	result.KeyDestroyed = true

	if contentStore != nil {
		err := contentStore.Delete(cfg.ArtifactCID)
		if err != nil {
			result.ContentDeleteError = err
			result.ContentDeleted = false
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
	contentStore storage.ContentStore,
) (*BatchExpungeResult, error) {
	if keyStore == nil {
		return nil, fmt.Errorf("artifact/expunge: nil key store")
	}

	result := &BatchExpungeResult{
		Total:  len(cids),
		Errors: make(map[string]error),
	}

	for _, cid := range cids {
		expResult, err := ExpungeArtifact(
			ExpungeConfig{ArtifactCID: cid},
			keyStore,
			contentStore,
		)
		if err != nil {
			result.Errors[cid.String()] = err
			continue
		}
		if expResult.KeyDestroyed {
			result.KeysDestroyed++
		}
		if expResult.ContentDeleted {
			result.ContentDeleted++
		}
	}

	return result, nil
}
