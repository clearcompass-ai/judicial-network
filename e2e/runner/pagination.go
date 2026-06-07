package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/clearcompass-ai/judicial-network/e2e/stack"
)

func init() {
	Register(Recipe{Name: "verify.pagination", Tags: []string{"verify", "pagination", "query"}, Run: verifyPagination})
}

// verify.pagination: prove the read-cost bound on the QueryBy* endpoints (tooling
// 2.3) — keyset pagination (?start, INCLUSIVE) plus a per-request cap (?count,
// clamped to [1, MaxScanCount]). It backfills with amendments so a root's signer
// recurs (Path-A same-signer rule), yielding a signer_did that spans several
// sequence numbers, then pages GET /v1/query/signer_did/{did} and asserts:
//   - the full result is ordered ASC by sequence,
//   - ?count bounds a page (count=1 ⇒ exactly the first entry),
//   - keyset paging (nextStart = lastSeq+1) reproduces the full result EXACTLY —
//     no gap, no duplicate, no over-read.
func verifyPagination(s *Session) error {
	ctx := context.Background()
	n := intEnv("E2E_PAGINATION_ENTRIES", 24)
	return forEachNetwork(s, func(name string, t stack.Target) error {
		before, _ := stack.HeadStatus(t.CertsDir, t.LedgerPort)
		// amend-ratio 0.5 ⇒ ~half the entries are Path-A amendments that reuse their
		// root's signer, so at least one signer_did spans multiple sequence numbers.
		st, err := stack.Backfill(t, s.Images.Ledger, n, 8, 0.5, 1)
		if err != nil {
			return fmt.Errorf("%s: backfill: %w", name, err)
		}
		target := before + st.Roots + st.Amendments
		if !stack.WaitDrained(t.CertsDir, t.LedgerPort, target,
			time.Duration(intEnv("E2E_DRAIN_TIMEOUT_MIN", 15))*time.Minute) {
			return fmt.Errorf("%s: backfill did not drain to tree_size %d", name, target)
		}

		client, err := caPinnedClient(filepath.Join(t.CertsDir, "ca.crt"))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		base := fmt.Sprintf("https://localhost:%d", t.LedgerPort)

		did, want, err := largestSignerCluster(ctx, client, base)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if len(want) < 2 {
			return fmt.Errorf("%s: largest signer_did cluster is %d (<2) — raise E2E_PAGINATION_ENTRIES or amend-ratio", name, len(want))
		}
		if err := assertSignerPagination(ctx, client, base, did, want); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fmt.Printf("  [PASS] %-8s signer_did pagination: %d entries, count-bounded + keyset cursor over /v1/query/signer_did\n", name, len(want))
		return nil
	})
}

// pageRow is the subset of the QueryBy* / scan EntryResponse this recipe asserts on.
type pageRow struct {
	SequenceNumber uint64 `json:"sequence_number"`
	SignerDID      string `json:"signer_did"`
}

// pageResp is the {entries, count} envelope writeEntriesJSON returns.
type pageResp struct {
	Entries []pageRow `json:"entries"`
	Count   int       `json:"count"`
}

func getPage(ctx context.Context, client *http.Client, url string) (pageResp, error) {
	var pr pageResp
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return pr, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return pr, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return pr, err
	}
	if err := json.Unmarshal(raw, &pr); err != nil {
		return pr, fmt.Errorf("decode %s: %w", url, err)
	}
	return pr, nil
}

// largestSignerCluster scans the log, finds the signer_did on the most entries
// (an amended root's signer), and fetches that signer's FULL result back through
// the very endpoint under test (count=MaxScanCount ⇒ all of them, ordered ASC).
func largestSignerCluster(ctx context.Context, client *http.Client, base string) (string, []pageRow, error) {
	scan, err := getPage(ctx, client, base+"/v1/query/scan?start=0&count=10000")
	if err != nil {
		return "", nil, fmt.Errorf("scan: %w", err)
	}
	byDID := map[string]int{}
	for _, e := range scan.Entries {
		if e.SignerDID != "" {
			byDID[e.SignerDID]++
		}
	}
	best, bestN := "", 0
	for did, c := range byDID {
		if c > bestN || (c == bestN && did < best) { // deterministic tie-break
			best, bestN = did, c
		}
	}
	if best == "" {
		return "", nil, fmt.Errorf("scan returned no signer_did to page")
	}
	all, err := getPage(ctx, client, base+"/v1/query/signer_did/"+url.PathEscape(best)+"?start=0&count=10000")
	if err != nil {
		return "", nil, fmt.Errorf("signer_did full query: %w", err)
	}
	return best, all.Entries, nil
}

// assertSignerPagination pins the 2.3 contract on /v1/query/signer_did/{did}
// given `want` (the full ordered result for did).
func assertSignerPagination(ctx context.Context, client *http.Client, base, did string, want []pageRow) error {
	q := func(start uint64, count int) (pageResp, error) {
		return getPage(ctx, client, fmt.Sprintf("%s/v1/query/signer_did/%s?start=%d&count=%d", base, url.PathEscape(did), start, count))
	}

	// Strictly ascending by sequence — the keyset ORDER the cursor relies on.
	for i := 1; i < len(want); i++ {
		if want[i].SequenceNumber <= want[i-1].SequenceNumber {
			return fmt.Errorf("full result not strictly ascending at %d: %d then %d", i, want[i-1].SequenceNumber, want[i].SequenceNumber)
		}
	}

	// Cap: count=1 returns EXACTLY the first entry — a hard per-request bound.
	if p, err := q(0, 1); err != nil {
		return err
	} else if len(p.Entries) != 1 || p.Count != 1 || p.Entries[0].SequenceNumber != want[0].SequenceNumber {
		return fmt.Errorf("count=1: got %d entries (count=%d), first seq mismatch vs %d", len(p.Entries), p.Count, want[0].SequenceNumber)
	}

	// Keyset: page size 2 from start=0, advancing past each page's last seq. The
	// concatenation must equal `want` (no gap, no dupe, no over-read).
	const pageSize = 2
	var got []pageRow
	for start := uint64(0); ; {
		p, err := q(start, pageSize)
		if err != nil {
			return err
		}
		if len(p.Entries) == 0 {
			break
		}
		if len(p.Entries) > pageSize {
			return fmt.Errorf("page over-read: %d entries exceed count=%d", len(p.Entries), pageSize)
		}
		if p.Count != len(p.Entries) {
			return fmt.Errorf("page count field %d != entries %d", p.Count, len(p.Entries))
		}
		got = append(got, p.Entries...)
		start = p.Entries[len(p.Entries)-1].SequenceNumber + 1
		if len(p.Entries) < pageSize {
			break // last (short) page
		}
	}
	if len(got) != len(want) {
		return fmt.Errorf("keyset paging yielded %d entries, want %d (gap or dupe)", len(got), len(want))
	}
	for i := range want {
		if got[i].SequenceNumber != want[i].SequenceNumber {
			return fmt.Errorf("keyset mismatch at %d: got seq %d, want %d", i, got[i].SequenceNumber, want[i].SequenceNumber)
		}
	}
	return nil
}
