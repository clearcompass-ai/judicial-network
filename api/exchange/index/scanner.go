/*
FILE PATH: exchange/index/scanner.go

DESCRIPTION:
    Sequential log scanner inspired by CT monitors. Reads entries
    from the operator in order, parses Domain Payloads, and builds
    local indexes (docket→position, DID→position, schema→position).

    The operator is a transparency log. It serves entries by position.
    It does NOT search. With 1B+ entries, search is the scanner's job,
    not the log's job. The scanner reads everything, the index stores
    the mappings, the business API queries the index.

    Runs as a background goroutine. Polls the operator for new entries
    at a configurable interval. Resilient to restarts — persists the
    last scanned position.

KEY DEPENDENCIES:
    - ortholog-sdk/log: OperatorQueryAPI.ScanFromPosition (guide §27.3)
*/
package index

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	sdklog "github.com/clearcompass-ai/ortholog-sdk/log"
)

// Scanner reads entries sequentially from an operator and feeds them
// to an IndexStore.
type Scanner struct {
	queryAPI  sdklog.OperatorQueryAPI
	store     *IndexStore
	logID     string
	batchSize uint64
	interval  time.Duration
}

// ScannerConfig configures the scanner.
type ScannerConfig struct {
	QueryAPI  sdklog.OperatorQueryAPI
	Store     *IndexStore
	LogID     string
	BatchSize uint64        // entries per poll (default 1000)
	Interval  time.Duration // poll interval (default 5s)
}

// NewScanner creates a log scanner.
func NewScanner(cfg ScannerConfig) *Scanner {
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 1000
	}
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	return &Scanner{
		queryAPI:  cfg.QueryAPI,
		store:     cfg.Store,
		logID:     cfg.LogID,
		batchSize: cfg.BatchSize,
		interval:  cfg.Interval,
	}
}

// Run starts the scanner. Blocks until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) {
	lastPos := s.store.LastScannedPosition(s.logID)
	log.Printf("index/scanner: starting from position %d on %s", lastPos, s.logID)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("index/scanner: stopped at position %d", lastPos)
			return
		case <-ticker.C:
			newPos, err := s.scanBatch(lastPos)
			if err != nil {
				log.Printf("index/scanner: scan error at %d: %v", lastPos, err)
				continue
			}
			if newPos > lastPos {
				lastPos = newPos
				s.store.SetLastScannedPosition(s.logID, lastPos)
			}
		}
	}
}

func (s *Scanner) scanBatch(fromPos uint64) (uint64, error) {
	entries, err := s.queryAPI.ScanFromPosition(fromPos, int(s.batchSize))
	if err != nil {
		return fromPos, err
	}

	if len(entries) == 0 {
		return fromPos, nil
	}

	maxPos := fromPos
	for _, meta := range entries {
		pos := meta.Position.Sequence
		if pos > maxPos {
			maxPos = pos
		}

		// Deserialize entry from canonical bytes.
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			continue
		}

		signerDID := entry.Header.SignerDID

		// Index by signer DID.
		s.store.AddDIDMapping(s.logID, signerDID, pos)

		// Parse Domain Payload for domain-specific fields.
		s.indexDomainPayload(pos, entry.DomainPayload)
	}

	return maxPos + 1, nil
}

func (s *Scanner) indexDomainPayload(pos uint64, payload []byte) {
	if len(payload) == 0 {
		return
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return
	}

	// Index docket_number if present.
	if docket, ok := m["docket_number"].(string); ok && docket != "" {
		s.store.AddDocketMapping(s.logID, docket, pos)
	}

	// Index artifact_cid if present.
	if cid, ok := m["artifact_cid"].(string); ok && cid != "" {
		s.store.AddCIDMapping(s.logID, cid, pos)
	}

	// Index party_name if present.
	if name, ok := m["party_name"].(string); ok && name != "" {
		s.store.AddPartyMapping(s.logID, name, pos)
	}

	// Index schema_ref if present.
	if schema, ok := m["schema_ref"].(string); ok && schema != "" {
		s.store.AddSchemaMapping(s.logID, schema, pos)
	}
}
