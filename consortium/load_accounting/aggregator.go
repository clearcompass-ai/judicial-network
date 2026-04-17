/*
FILE PATH: consortium/load_accounting/aggregator.go

DESCRIPTION:
    Computes deterministic settlement between two cosigned tree head
    boundaries. Uses ScanFromPosition (guide §27.3) to iterate entries
    in the bounded range and ClassifyEntry (guide §11.1) to identify
    entry types. Counts per-county contributions for settlement.

    The aggregator is deterministic: given the same tree head boundaries,
    every node computes the same settlement ledger. This is critical
    for dispute resolution — any party can independently verify the
    aggregation.

KEY DEPENDENCIES:
    - ortholog-sdk/log: OperatorQueryAPI.ScanFromPosition (guide §27.3)
    - ortholog-sdk/builder: ClassifyEntry (guide §11.1)
    - ortholog-sdk/types: EntryWithMetadata, CosignedTreeHead
*/
package load_accounting

import (
	"encoding/json"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/log"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// SettlementLedger records per-member usage between two tree head
// boundaries.
type SettlementLedger struct {
	// StartTreeHead is the lower boundary (inclusive).
	StartPos uint64 `json:"start_pos"`

	// EndTreeHead is the upper boundary (exclusive).
	EndPos uint64 `json:"end_pos"`

	// MemberUsage maps member DID → usage counters.
	MemberUsage map[string]*MemberUsage `json:"member_usage"`

	// TotalEntries is the total entry count in the range.
	TotalEntries uint64 `json:"total_entries"`
}

// MemberUsage tracks a single member's contributions in a settlement
// period.
type MemberUsage struct {
	EntryCount      uint64 `json:"entry_count"`
	DelegationCount uint64 `json:"delegation_count"`
	SchemaCount     uint64 `json:"schema_count"`
	CommentaryCount uint64 `json:"commentary_count"`
	AmendmentCount  uint64 `json:"amendment_count"`
	OtherCount      uint64 `json:"other_count"`
}

// Aggregator computes settlement ledgers from log scans.
type Aggregator struct {
	queryAPI log.OperatorQueryAPI
}

// NewAggregator creates an aggregator bound to a specific log's query API.
func NewAggregator(queryAPI log.OperatorQueryAPI) *Aggregator {
	return &Aggregator{queryAPI: queryAPI}
}

// ComputeSettlement scans entries between startPos and endPos and
// produces a deterministic settlement ledger.
func (a *Aggregator) ComputeSettlement(startPos, endPos uint64) (*SettlementLedger, error) {
	if startPos >= endPos {
		return nil, fmt.Errorf("load_accounting/aggregator: start %d >= end %d", startPos, endPos)
	}

	ledger := &SettlementLedger{
		StartPos:    startPos,
		EndPos:      endPos,
		MemberUsage: make(map[string]*MemberUsage),
	}

	// Scan entries in the bounded range.
	scanResult, err := a.queryAPI.ScanFromPosition(log.ScanParams{
		StartPosition: startPos,
		Limit:         endPos - startPos,
	})
	if err != nil {
		return nil, fmt.Errorf("load_accounting/aggregator: scan: %w", err)
	}

	for _, entry := range scanResult.Entries {
		ledger.TotalEntries++

		signerDID := entry.Entry.SignerDID()
		usage := ledger.ensureMember(signerDID)

		classification := builder.ClassifyEntry(entry.Entry)
		switch classification.Type {
		case "delegation":
			usage.DelegationCount++
		case "schema":
			usage.SchemaCount++
		case "commentary":
			usage.CommentaryCount++
		case "amendment", "scope_amendment":
			usage.AmendmentCount++
		default:
			usage.OtherCount++
		}
		usage.EntryCount++
	}

	return ledger, nil
}

// ensureMember returns the MemberUsage for a DID, creating it if needed.
func (l *SettlementLedger) ensureMember(did string) *MemberUsage {
	if u, ok := l.MemberUsage[did]; ok {
		return u
	}
	u := &MemberUsage{}
	l.MemberUsage[did] = u
	return u
}

// ToJSON serializes the ledger for on-log publication or off-log audit.
func (l *SettlementLedger) ToJSON() ([]byte, error) {
	return json.Marshal(l)
}

// ComputeArtifactUsage scans a cases log between two positions and
// extracts per-member artifact storage usage by reading artifact_cid
// fields from Domain Payloads. This is a domain-layer scan — the SDK
// doesn't know about artifact_cid fields (SDK-D6: Domain Payload
// opacity is absolute).
func (a *Aggregator) ComputeArtifactUsage(
	startPos, endPos uint64,
	extractCID func(entry types.EntryWithMetadata) (string, int64, bool),
) (map[string]int64, error) {
	if extractCID == nil {
		return nil, fmt.Errorf("load_accounting/aggregator: nil extractCID function")
	}

	usage := make(map[string]int64) // member DID → total bytes

	scanResult, err := a.queryAPI.ScanFromPosition(log.ScanParams{
		StartPosition: startPos,
		Limit:         endPos - startPos,
	})
	if err != nil {
		return nil, fmt.Errorf("load_accounting/aggregator: artifact scan: %w", err)
	}

	for _, entry := range scanResult.Entries {
		_, sizeBytes, hasCID := extractCID(entry)
		if !hasCID {
			continue
		}
		signerDID := entry.Entry.SignerDID()
		usage[signerDID] += sizeBytes
	}

	return usage, nil
}
