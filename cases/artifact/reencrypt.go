/*
FILE PATH:
    cases/artifact/reencrypt.go

DESCRIPTION:
    Implements Tier 1 AES-GCM re-encryption for key rotation. Only AES-GCM
    artifacts are re-encrypted — PRE transforms the access path via KFrags,
    not the ciphertext.

KEY ARCHITECTURAL DECISIONS:
    - content_digest UNCHANGED: re-encryption does not modify plaintext.
      artifact_cid CHANGES: new key → new ciphertext → new CID.
    - Delegates to SDK lifecycle.ReEncryptWithGrant for the actual
      decrypt → re-encrypt → push cycle. No local crypto.
    - Concurrent batch mode with configurable parallelism and retry.
    - Old key cryptographically erased after successful re-encryption.

OVERVIEW:
    Per artifact: (1) ReEncryptWithGrant → new CT + new key
    (2) new_cid = storage.Compute(newCT) (3) push + store new key
    (4) delete old key (cryptographic erasure). Batch mode: semaphore
    concurrency, per-CID retry with configurable attempts/delay.

KEY DEPENDENCIES:
    - ortholog-sdk/lifecycle: ReEncryptWithGrant for SDK re-encryption cycle
    - ortholog-sdk/storage: ContentStore for push/delete, CID for addressing
*/
package artifact

import (
	"fmt"
	"sync"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// -------------------------------------------------------------------------------------------------
// 1) Types
// -------------------------------------------------------------------------------------------------

// ReencryptConfig configures a single re-encryption operation.
type ReencryptConfig struct {
	OldCID              storage.CID
	DeleteOldCiphertext bool
}

// ReencryptResult holds the outcome of a single re-encryption.
type ReencryptResult struct {
	OldCID                 storage.CID
	NewCID                 storage.CID
	ContentDigestUnchanged bool
}

// BatchReencryptConfig configures a batch re-encryption operation.
type BatchReencryptConfig struct {
	CIDs                []storage.CID
	Concurrency         int
	DeleteOldCiphertext bool
	ProgressCallback    func(completed, total int, lastCID storage.CID, err error)
	RetryAttempts       int
	RetryDelay          time.Duration
}

// BatchReencryptResult holds the aggregate outcome.
type BatchReencryptResult struct {
	Total     int
	Succeeded int
	Failed    int
	Results   map[string]storage.CID
	Errors    map[string]error
}

// -------------------------------------------------------------------------------------------------
// 2) ReencryptArtifact — single artifact
// -------------------------------------------------------------------------------------------------

func ReencryptArtifact(
	cfg ReencryptConfig,
	keyStore lifecycle.ArtifactKeyStore,
	contentStore storage.ContentStore,
) (*ReencryptResult, error) {
	if cfg.OldCID.IsZero() {
		return nil, fmt.Errorf("artifact/reencrypt: zero old CID")
	}

	sdkResult, err := lifecycle.ReEncryptWithGrant(lifecycle.ReEncryptWithGrantParams{
		OldCID:              cfg.OldCID,
		KeyStore:            keyStore,
		ContentStore:        contentStore,
		DeleteOldCiphertext: cfg.DeleteOldCiphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("artifact/reencrypt: %w", err)
	}

	return &ReencryptResult{
		OldCID:                 cfg.OldCID,
		NewCID:                 sdkResult.NewCID,
		ContentDigestUnchanged: true,
	}, nil
}

// -------------------------------------------------------------------------------------------------
// 3) BatchReencrypt — multiple artifacts
// -------------------------------------------------------------------------------------------------

func BatchReencrypt(
	cfg BatchReencryptConfig,
	keyStore lifecycle.ArtifactKeyStore,
	contentStore storage.ContentStore,
) (*BatchReencryptResult, error) {
	if keyStore == nil || contentStore == nil {
		return nil, fmt.Errorf("artifact/reencrypt: nil key store or content store")
	}

	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	result := &BatchReencryptResult{
		Total:   len(cfg.CIDs),
		Results: make(map[string]storage.CID),
		Errors:  make(map[string]error),
	}

	if len(cfg.CIDs) == 0 {
		return result, nil
	}

	if concurrency == 1 {
		for i, cid := range cfg.CIDs {
			reResult, err := reencryptWithRetry(cid, cfg, keyStore, contentStore)
			if err != nil {
				result.Failed++
				result.Errors[cid.String()] = err
			} else {
				result.Succeeded++
				result.Results[cid.String()] = reResult.NewCID
			}
			if cfg.ProgressCallback != nil {
				cfg.ProgressCallback(i+1, result.Total, cid, err)
			}
		}
		return result, nil
	}

	var mu sync.Mutex
	completed := 0
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, cid := range cfg.CIDs {
		wg.Add(1)
		sem <- struct{}{}
		go func(c storage.CID) {
			defer wg.Done()
			defer func() { <-sem }()

			reResult, err := reencryptWithRetry(c, cfg, keyStore, contentStore)

			mu.Lock()
			completed++
			current := completed
			if err != nil {
				result.Failed++
				result.Errors[c.String()] = err
			} else {
				result.Succeeded++
				result.Results[c.String()] = reResult.NewCID
			}
			mu.Unlock()

			if cfg.ProgressCallback != nil {
				cfg.ProgressCallback(current, result.Total, c, err)
			}
		}(cid)
	}

	wg.Wait()
	return result, nil
}

// -------------------------------------------------------------------------------------------------
// 4) Retry helper
// -------------------------------------------------------------------------------------------------

func reencryptWithRetry(
	cid storage.CID,
	cfg BatchReencryptConfig,
	keyStore lifecycle.ArtifactKeyStore,
	contentStore storage.ContentStore,
) (*ReencryptResult, error) {
	var lastErr error
	attempts := cfg.RetryAttempts + 1
	if attempts < 1 {
		attempts = 1
	}
	delay := cfg.RetryDelay
	if delay <= 0 {
		delay = 1 * time.Second
	}

	for attempt := 0; attempt < attempts; attempt++ {
		result, err := ReencryptArtifact(
			ReencryptConfig{
				OldCID:              cid,
				DeleteOldCiphertext: cfg.DeleteOldCiphertext,
			},
			keyStore,
			contentStore,
		)
		if err == nil {
			return result, nil
		}
		lastErr = err
		if attempt < attempts-1 {
			time.Sleep(delay)
		}
	}
	return nil, lastErr
}
