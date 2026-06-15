package scenario

// Blind-consumer read-back: reconstruct the provisioned cases the way a
// third-party CONSUMER would — from the ledger's public read surface alone, with
// no registry, no keys, and no trust in the provisioning side. It reads the
// cosigned head, fetches every entry's canonical bytes over the open
// /v1/entries/{seq}/raw endpoint (via the SDK's HTTPEntryFetcher, which follows
// the ledger's WAL-inline vs bytestore-redirect serving), deserializes each
// envelope, and groups the domain payloads by docket. The on-log bytes are the
// only input — so a clean audit proves the data is real, readable, and complete
// to anyone, not just to the tool that wrote it.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/baseproof/baseproof/core/envelope"
	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/types"
)

// AuditedCase is one case reconstructed purely from the log. Events are the
// on-log event_types observed for this docket, in sequence order.
type AuditedCase struct {
	Docket    string
	Caption   string
	Specialty string
	Events    []string
}

// Has reports whether the case carries an entry of the given event_type.
func (c *AuditedCase) Has(eventType string) bool {
	for _, e := range c.Events {
		if e == eventType {
			return true
		}
	}
	return false
}

// LedgerAuditReport is the blind-consumer view of a provisioned ledger.
type LedgerAuditReport struct {
	TreeSize    uint64
	Decoded     int                     // entries successfully fetched + deserialized
	EventCounts map[string]int          // event_type → count across the whole log
	Cases       map[string]*AuditedCase // by docket_number
	Complete    []string                // dockets with case_initiation + responsive_pleading + final_judgment
	Incomplete  []string                // dockets missing one of those
}

// AuditLedger reconstructs cases as a consumer would. logDID is the log the
// ledger serves (the entry Destination). client must trust the ledger's server
// cert (reads are open; no client cert needed).
func AuditLedger(ctx context.Context, baseURL, logDID string, client *http.Client) (*LedgerAuditReport, error) {
	if client == nil {
		client = &http.Client{}
	}
	head, err := NewLedgerReader(baseURL, client).Head(ctx)
	if err != nil {
		return nil, fmt.Errorf("read tree head: %w", err)
	}
	fetcher, err := sdklog.NewHTTPEntryFetcher(sdklog.HTTPEntryFetcherConfig{
		BaseURL: baseURL,
		LogDID:  logDID,
		Client:  client,
	})
	if err != nil {
		return nil, fmt.Errorf("new entry fetcher: %w", err)
	}

	rep := &LedgerAuditReport{
		TreeSize:    head.TreeSize,
		EventCounts: map[string]int{},
		Cases:       map[string]*AuditedCase{},
	}
	for seq := uint64(0); seq < head.TreeSize; seq++ {
		fe, ferr := fetcher.Fetch(ctx, types.LogPosition{LogDID: logDID, Sequence: seq})
		if ferr != nil {
			return rep, fmt.Errorf("fetch entry %d: %w", seq, ferr)
		}
		entry, derr := envelope.Deserialize(fe.CanonicalBytes)
		if derr != nil {
			return rep, fmt.Errorf("deserialize entry %d: %w", seq, derr)
		}
		rep.Decoded++

		var p struct {
			EventType string `json:"event_type"`
			Docket    string `json:"docket_number"`
			Caption   string `json:"caption"`
			Specialty string `json:"specialty"`
		}
		_ = json.Unmarshal(entry.DomainPayload, &p) // non-JSON / non-case entries: zero values
		if p.EventType != "" {
			rep.EventCounts[p.EventType]++
		}
		if p.Docket == "" {
			continue // delegations, genesis-seed, anything not case-bound
		}
		c := rep.Cases[p.Docket]
		if c == nil {
			c = &AuditedCase{Docket: p.Docket}
			rep.Cases[p.Docket] = c
		}
		if p.EventType != "" {
			c.Events = append(c.Events, p.EventType)
		}
		if p.Caption != "" {
			c.Caption = p.Caption
		}
		if p.Specialty != "" {
			c.Specialty = p.Specialty
		}
	}

	for docket, c := range rep.Cases {
		if c.Has("case_initiation") && c.Has("responsive_pleading") && c.Has("final_judgment") {
			rep.Complete = append(rep.Complete, docket)
		} else {
			rep.Incomplete = append(rep.Incomplete, docket)
		}
	}
	sort.Strings(rep.Complete)
	sort.Strings(rep.Incomplete)
	return rep, nil
}
