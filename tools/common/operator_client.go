package common

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OperatorClient reads entries from the log operator's HTTP API.
// Read-only. No privilege. Public data.
type OperatorClient struct {
	baseURL string
	client  *http.Client
}

// NewOperatorClient creates a client pointing at the operator.
func NewOperatorClient(baseURL string) *OperatorClient {
	return &OperatorClient{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

// RawEntry is the JSON response from the operator's entry read endpoint.
type RawEntry struct {
	Sequence         uint64 `json:"sequence"`
	CanonicalHex     string `json:"canonical_hex"`
	LogTimeUnixMicro int64  `json:"log_time_unix_micro"`
	SigAlgoID        uint16 `json:"sig_algo_id,omitempty"`
	SignatureHex     string `json:"signature_hex,omitempty"`
}

// FetchEntry reads a single entry by sequence number.
// Returns nil, nil if the entry does not exist (404).
func (c *OperatorClient) FetchEntry(seq uint64) (*RawEntry, error) {
	url := fmt.Sprintf("%s/v1/entries/%d", c.baseURL, seq)

	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("operator: fetch %d: %w", seq, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("operator: read %d: %w", seq, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("operator: HTTP %d for seq %d: %s", resp.StatusCode, seq, body)
	}

	var entry RawEntry
	if err := json.Unmarshal(body, &entry); err != nil {
		return nil, fmt.Errorf("operator: parse %d: %w", seq, err)
	}
	return &entry, nil
}

// ScanFrom reads a batch of entries starting at startPos.
// Returns up to count entries. Returns empty slice (not error) at log end.
func (c *OperatorClient) ScanFrom(startPos uint64, count int) ([]RawEntry, error) {
	url := fmt.Sprintf("%s/v1/entries?start=%d&count=%d", c.baseURL, startPos, count)

	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("operator: scan from %d: %w", startPos, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("operator: read scan: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("operator: scan HTTP %d: %s", resp.StatusCode, body)
	}

	var entries []RawEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("operator: parse scan: %w", err)
	}
	return entries, nil
}

// TreeHead fetches the operator's current tree head (latest checkpoint).
func (c *OperatorClient) TreeHead() (map[string]any, error) {
	resp, err := c.client.Get(c.baseURL + "/v1/tree/head")
	if err != nil {
		return nil, fmt.Errorf("operator: tree head: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("operator: read tree head: %w", err)
	}

	var result map[string]any
	json.Unmarshal(body, &result)
	return result, nil
}
