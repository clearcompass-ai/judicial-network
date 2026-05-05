/*
FILE PATH: cmd/judicial-cli/read.go

DESCRIPTION:

	Read-side subcommands. All four are thin wrappers over the
	ledger's pure-JSON endpoints (no binary wire format on the
	wire), so a developer can also just `curl` them — these are
	here for ergonomic flag handling and consistent error paths.

ENDPOINTS WRAPPED (all under ledger/api/server.go:19-49):

	GET /v1/entries/{seq}                 → JSON metadata
	GET /v1/entries/{seq}/raw             → wire bytes (hex)
	GET /v1/tree/head                     → cosigned tree head
	GET /v1/tree/inclusion/{seq}          → Merkle inclusion proof
	GET /v1/entries-hash/{hashHex}        → hash-keyed lookup w/ WAL state
*/
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

// ─── get ───────────────────────────────────────────────────────

func runGet(args []string) error {
	fs := flagSet("get")
	endpoint := fs.String("endpoint", "", "ledger base URL")
	seq := fs.Uint64("seq", 0, "entry sequence number (required)")
	raw := fs.Bool("raw", false, "fetch /raw wire bytes instead of metadata JSON")
	if err := fs.Parse(args); err != nil {
		return argsErr("parsing flags: %w", err)
	}
	if *endpoint == "" || *seq == 0 {
		return argsErr("--endpoint and --seq (>0) are required")
	}

	path := fmt.Sprintf("/v1/entries/%d", *seq)
	if *raw {
		path += "/raw"
	}
	body, status, err := httpGet(*endpoint + path)
	if err != nil {
		return transportErr("%v", err)
	}
	return printOrError(status, body, *raw)
}

// ─── head ──────────────────────────────────────────────────────

func runHead(args []string) error {
	fs := flagSet("head")
	endpoint := fs.String("endpoint", "", "ledger base URL")
	size := fs.Int("size", 0, "optional tree size (defaults to current)")
	if err := fs.Parse(args); err != nil {
		return argsErr("parsing flags: %w", err)
	}
	if *endpoint == "" {
		return argsErr("--endpoint is required")
	}

	path := "/v1/tree/head"
	if *size > 0 {
		path += "?size=" + strconv.Itoa(*size)
	}
	body, status, err := httpGet(*endpoint + path)
	if err != nil {
		return transportErr("%v", err)
	}
	return printOrError(status, body, false)
}

// ─── inclusion ─────────────────────────────────────────────────

func runInclusion(args []string) error {
	fs := flagSet("inclusion")
	endpoint := fs.String("endpoint", "", "ledger base URL")
	seq := fs.Uint64("seq", 0, "entry sequence number (required)")
	if err := fs.Parse(args); err != nil {
		return argsErr("parsing flags: %w", err)
	}
	if *endpoint == "" || *seq == 0 {
		return argsErr("--endpoint and --seq (>0) are required")
	}
	body, status, err := httpGet(fmt.Sprintf("%s/v1/tree/inclusion/%d", *endpoint, *seq))
	if err != nil {
		return transportErr("%v", err)
	}
	return printOrError(status, body, false)
}

// ─── wait ──────────────────────────────────────────────────────

// runWait polls /v1/entries-hash/{hex} until the ledger reports
// a sequenced (or shipped) state. Useful immediately after submit
// to bridge the SCT → Sequencer → entry-index window (typically <1s
// against an in-process tessera).
func runWait(args []string) error {
	fs := flagSet("wait")
	endpoint := fs.String("endpoint", "", "ledger base URL")
	hash := fs.String("hash", "", "canonical hash hex (64 chars) from `submit`")
	timeout := fs.Duration("timeout", 30*time.Second, "give up after this long")
	pollEvery := fs.Duration("poll", 250*time.Millisecond, "poll interval")
	if err := fs.Parse(args); err != nil {
		return argsErr("parsing flags: %w", err)
	}
	if *endpoint == "" || *hash == "" {
		return argsErr("--endpoint and --hash are required")
	}
	if len(*hash) != 64 {
		return argsErr("--hash must be 64 hex chars (got %d)", len(*hash))
	}

	deadline := time.Now().Add(*timeout)
	url := fmt.Sprintf("%s/v1/entries-hash/%s", *endpoint, *hash)
	for {
		body, status, err := httpGet(url)
		if err != nil {
			return transportErr("%v", err)
		}
		if status == http.StatusOK {
			// Body is JSON with at least {"state": "..."}.
			var probe struct {
				State    string `json:"state"`
				Sequence uint64 `json:"sequence,omitempty"`
			}
			if err := json.Unmarshal(body, &probe); err != nil {
				return wireErr("parse hash-lookup response: %w", err)
			}
			if probe.State == "sequenced" || probe.State == "shipped" {
				fmt.Printf("state=%s sequence=%d\n", probe.State, probe.Sequence)
				fmt.Println(string(body))
				return nil
			}
			// state=pending → keep polling.
		} else if status != http.StatusNotFound {
			return remoteErr("HTTP %d: %s", status, string(body))
		}
		if time.Now().After(deadline) {
			return remoteErr("timeout after %s; entry not yet sequenced (last status %d)",
				timeout, status)
		}
		time.Sleep(*pollEvery)
	}
}

// ─── shared helpers ────────────────────────────────────────────

func httpGet(url string) ([]byte, int, error) {
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, 0, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}
	return body, resp.StatusCode, nil
}

func printOrError(status int, body []byte, raw bool) error {
	if status == http.StatusOK {
		// /raw returns octet-stream; everyone else returns JSON.
		// Pretty-print JSON if we can; otherwise dump bytes.
		if raw {
			_, _ = os.Stdout.Write(body)
			return nil
		}
		var pretty interface{}
		if err := json.Unmarshal(body, &pretty); err == nil {
			out, _ := json.MarshalIndent(pretty, "", "  ")
			fmt.Println(string(out))
			return nil
		}
		fmt.Println(string(body))
		return nil
	}
	return remoteErr("HTTP %d: %s", status, string(body))
}
