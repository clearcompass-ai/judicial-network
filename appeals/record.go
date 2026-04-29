/*
FILE PATH: appeals/record.go
DESCRIPTION: Record on appeal — certified copy of lower court entries.
KEY ARCHITECTURAL DECISIONS:
    - Queries lower court operator via QueryByTargetRoot for all entries.
    - Decrypts source artifacts via caller-supplied SourceDecryptor.
    - Re-encrypts under appellate owner DID via artifact.PublishArtifact.
    - Produces manifest commentary listing all transferred CIDs.

BUGFIX NOTES (§5.2):
    - Prior version set Plaintext: []byte(payload.ArtifactCID) — it
      re-encrypted the source CID's string bytes rather than the artifact
      content. Appellate artifacts were garbage.
    - This version performs real retrieve-then-publish. The trust-boundary
      reality is that either the appellate court runs this on the source
      operator's trust side (clerks with direct key-store access), OR
      the source operator issues a grant and the appellate side unwraps
      with its recipient private key. Both are valid operational modes;
      neither fits inside one helper without a caller hook.
    - SourceDecryptor is that hook. TransferRecord handles ortholog
      plumbing; the caller supplies the crypto boundary. A reference
      DirectKeySourceDecryptor handles in-trust-boundary deployments.

OVERVIEW: TransferRecord → re-encrypted artifacts + manifest commentary.
KEY DEPENDENCIES: ortholog-sdk/builder, log.OperatorQueryAPI, cases/artifact
*/
package appeals

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	sdkartifact "github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"

	"github.com/clearcompass-ai/judicial-network/cases/artifact"
)

// RecordQuerier discovers entries by target root on the lower court log.
// Satisfied by log.OperatorQueryAPI (structural typing).
type RecordQuerier interface {
	QueryByTargetRoot(pos types.LogPosition) ([]types.EntryWithMetadata, error)
}

// SourceDecryptor decrypts a source-court artifact to plaintext.
//
// Implementations decide trust model:
//   - Direct-key: look up the AES key in the source KeyStore, fetch
//     ciphertext, call artifact.DecryptArtifact.
//   - Grant-mediated: call artifact.RetrieveArtifact on the source,
//     unwrap the returned key with the appellate recipient private key,
//     decrypt.
//   - HSM-backed: hand ciphertext + CID to an HSM that holds material.
//
// TransferRecord zeroes the returned plaintext immediately after re-encryption.
type SourceDecryptor interface {
	DecryptSource(sourceCID storage.CID, sourceEntry *envelope.Entry) ([]byte, error)
}

// AppellateDeps groups the appellate-side SDK injection points.
type AppellateDeps struct {
	ContentStore storage.ContentStore
	KeyStore     lifecycle.ArtifactKeyStore
	DelKeyStore  artifact.DelegationKeyStore
	Extractor    schema.SchemaParameterExtractor
	Fetcher      types.EntryFetcher
	Resolver     did.DIDResolver
}

// RecordTransferConfig configures a record-on-appeal transfer.
type RecordTransferConfig struct {
	Destination string // DID of target exchange. Required.
	SignerDID          string
	LowerCourtCasePos  types.LogPosition
	AppellateSchemaRef types.LogPosition
	AppellateOwnerDID  string
	EventTime          int64
}

// TransferredItem records one successfully transferred artifact.
type TransferredItem struct {
	SourceCID      string
	TargetCID      string
	ContentDigest  string
	DocumentType   string
	SourceEntryPos types.LogPosition
	Scheme         string
}

// RecordTransferResult holds the outcome.
type RecordTransferResult struct {
	ManifestEntry   *envelope.Entry
	Transferred     []TransferredItem
	TransferredCIDs []string
	ErrorCount      int
	ErrorsByCID     map[string]string
}

// TransferRecord queries the lower court for all entries on a case,
// decrypts their artifacts via the caller-supplied SourceDecryptor,
// re-encrypts under appellate keys via artifact.PublishArtifact, and
// produces a manifest commentary entry for the appellate log.
func TransferRecord(
	cfg RecordTransferConfig,
	querier RecordQuerier,
	decryptor SourceDecryptor,
	appellate AppellateDeps,
) (*RecordTransferResult, error) {
	if cfg.SignerDID == "" {
		return nil, fmt.Errorf("appeals/record: empty signer DID")
	}
	if cfg.AppellateOwnerDID == "" {
		return nil, fmt.Errorf("appeals/record: empty appellate owner DID")
	}
	if decryptor == nil {
		return nil, fmt.Errorf("appeals/record: nil source decryptor")
	}

	entries, err := querier.QueryByTargetRoot(cfg.LowerCourtCasePos)
	if err != nil {
		return nil, fmt.Errorf("appeals/record: query lower court: %w", err)
	}

	result := &RecordTransferResult{
		ErrorsByCID: make(map[string]string),
	}

	for _, meta := range entries {
		sourceEntry, dErr := envelope.Deserialize(meta.CanonicalBytes)
		if dErr != nil || len(sourceEntry.DomainPayload) == 0 {
			continue
		}

		var p struct {
			ArtifactCID   string `json:"artifact_cid"`
			ContentDigest string `json:"content_digest"`
			DocumentType  string `json:"document_type"`
			Scheme        string `json:"artifact_encryption"`
		}
		if json.Unmarshal(sourceEntry.DomainPayload, &p) != nil || p.ArtifactCID == "" {
			continue
		}

		sourceCID, cidErr := storage.ParseCID(p.ArtifactCID)
		if cidErr != nil {
			result.ErrorCount++
			result.ErrorsByCID[p.ArtifactCID] = "invalid source CID: " + cidErr.Error()
			continue
		}

		// 1. Decrypt source.
		plaintext, decErr := decryptor.DecryptSource(sourceCID, sourceEntry)
		if decErr != nil {
			result.ErrorCount++
			result.ErrorsByCID[sourceCID.String()] = "decrypt: " + decErr.Error()
			continue
		}

		// 2. Re-publish under appellate configuration.
		published, pubErr := artifact.PublishArtifact(
			artifact.PublishConfig{
				Plaintext: plaintext,
				SchemaRef: cfg.AppellateSchemaRef,
				OwnerDID:  cfg.AppellateOwnerDID,
				Metadata: map[string]string{
					"document_type":       p.DocumentType,
					"source_court_case":   cfg.LowerCourtCasePos.String(),
					"source_entry_seq":    fmt.Sprintf("%d", meta.Position.Sequence),
					"source_artifact_cid": sourceCID.String(),
				},
			},
			appellate.ContentStore, appellate.KeyStore, appellate.DelKeyStore,
			appellate.Extractor, appellate.Fetcher, appellate.Resolver,
		)

		// 3. Zero plaintext immediately after use.
		for i := range plaintext {
			plaintext[i] = 0
		}

		if pubErr != nil {
			result.ErrorCount++
			result.ErrorsByCID[sourceCID.String()] = "publish: " + pubErr.Error()
			continue
		}

		item := TransferredItem{
			SourceCID:      sourceCID.String(),
			TargetCID:      published.ArtifactCID.String(),
			ContentDigest:  published.ContentDigest.String(),
			DocumentType:   p.DocumentType,
			SourceEntryPos: meta.Position,
			Scheme:         published.Scheme,
		}
		result.Transferred = append(result.Transferred, item)
		result.TransferredCIDs = append(result.TransferredCIDs, item.TargetCID)
	}

	manifestPayload, _ := json.Marshal(map[string]interface{}{
		"manifest_type":    "record_on_appeal",
		"lower_court_case": cfg.LowerCourtCasePos.String(),
		"transferred":      result.Transferred,
		"artifact_count":   len(result.Transferred),
		"error_count":      result.ErrorCount,
	})

	manifest, err := builder.BuildCommentary(builder.CommentaryParams{
		Destination: cfg.Destination,
		SignerDID: cfg.SignerDID,
		Payload:   manifestPayload,
		EventTime: cfg.EventTime,
	})
	if err != nil {
		return result, fmt.Errorf("appeals/record: build manifest: %w", err)
	}
	result.ManifestEntry = manifest
	return result, nil
}

// DirectKeySourceDecryptor implements SourceDecryptor for deployments
// where the transfer runs on the source operator's trust boundary
// (clerks with direct key-store access). AES-GCM artifacts only.
type DirectKeySourceDecryptor struct {
	ContentStore storage.ContentStore
	KeyStore     lifecycle.ArtifactKeyStore
}

// DecryptSource fetches ciphertext, looks up the AES key, and decrypts.
func (d *DirectKeySourceDecryptor) DecryptSource(
	sourceCID storage.CID,
	_ *envelope.Entry,
) ([]byte, error) {
	if d.ContentStore == nil {
		return nil, fmt.Errorf("direct-key decryptor: nil content store")
	}
	if d.KeyStore == nil {
		return nil, fmt.Errorf("direct-key decryptor: nil key store")
	}
	key, err := d.KeyStore.Get(sourceCID)
	if err != nil {
		return nil, fmt.Errorf("key lookup: %w", err)
	}
	if key == nil {
		return nil, fmt.Errorf("key not found for %s (PRE or expunged)", sourceCID)
	}
	ciphertext, err := d.ContentStore.Fetch(sourceCID)
	if err != nil {
		return nil, fmt.Errorf("fetch ciphertext: %w", err)
	}
	return sdkartifact.DecryptArtifact(ciphertext, *key)
}
