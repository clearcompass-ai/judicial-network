package aggregator

import (
	"context"
	"log"
	"time"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

// Scanner polls the operator for new entries and indexes them into Postgres.
type Scanner struct {
	operator     *common.OperatorClient
	db           *common.DB
	indexer      *Indexer
	deserializer *Deserializer
	logDIDs      []string
	batchSize    int
	pollInterval time.Duration
}

// NewScanner creates a scanner that reads from the operator and writes to Postgres.
func NewScanner(cfg common.Config, operator *common.OperatorClient, db *common.DB) *Scanner {
	return &Scanner{
		operator:     operator,
		db:           db,
		indexer:      NewIndexer(db),
		deserializer: NewDeserializer(),
		logDIDs:      cfg.LogDIDs(),
		batchSize:    cfg.AggregatorBatchSize,
		pollInterval: cfg.AggregatorPollInterval,
	}
}

// Run starts the polling loop. Blocks until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) error {
	log.Printf("aggregator: starting scanner, poll=%s, batch=%d, logs=%d",
		s.pollInterval, s.batchSize, len(s.logDIDs))

	for {
		select {
		case <-ctx.Done():
			log.Println("aggregator: scanner stopped")
			return nil
		case <-time.After(s.pollInterval):
			for _, logDID := range s.logDIDs {
				if err := s.scanLog(ctx, logDID); err != nil {
					log.Printf("aggregator: scan %s: %v", logDID, err)
				}
			}
		}
	}
}

// RunOnce scans all logs once (for testing and manual runs).
func (s *Scanner) RunOnce(ctx context.Context) error {
	for _, logDID := range s.logDIDs {
		if err := s.scanLog(ctx, logDID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scanner) scanLog(ctx context.Context, logDID string) error {
	watermark, err := s.db.GetWatermark(logDID)
	if err != nil {
		return err
	}

	startPos := watermark + 1
	if watermark == 0 {
		startPos = 0
	}

	entries, err := s.operator.ScanFrom(startPos, s.batchSize)
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		return nil
	}

	indexed := 0
	for _, raw := range entries {
		classified, err := s.deserializer.Classify(logDID, raw)
		if err != nil {
			log.Printf("aggregator: classify seq=%d: %v", raw.Sequence, err)
			continue
		}

		if err := s.indexer.Index(ctx, classified); err != nil {
			log.Printf("aggregator: index seq=%d type=%s: %v",
				raw.Sequence, classified.EntryType, err)
			continue
		}
		indexed++
	}

	lastSeq := entries[len(entries)-1].Sequence
	if err := s.db.UpdateWatermark(logDID, lastSeq); err != nil {
		return err
	}

	if indexed > 0 {
		log.Printf("aggregator: %s indexed %d entries (seq %d→%d)",
			logDID, indexed, startPos, lastSeq)
	}

	return nil
}
