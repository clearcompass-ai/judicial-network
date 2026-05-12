// FILE PATH: cmd/judicial-cli/onboard_test.go
//
// Tests for the Phase 8 `onboard` subcommand dispatcher. The
// cryptographic bootstrap itself is covered by onboarding/
// bootstrap_test.go; this file covers the CLI surface:
//
//  1. Missing --method or --court returns exit code 2.
//  2. Unknown --method returns exit code 2 with a clear
//     message naming the three accepted modes.
//  3. Valid --method + --court emits a JSON certificate to
//     stdout and an ASCII Summary line.
//  4. --out=<path> writes the JSON to the file and still
//     prints the Summary to stdout.
//  5. onboardUsage returns a stable banner referencing all
//     three modes.
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunOnboard_MissingFlags(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runOnboard(nil, &out, &errBuf)
	if code != 2 {
		t.Fatalf("missing flags exit code = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "--method") {
		t.Errorf("stderr should mention --method, got %s", errBuf.String())
	}
}

func TestRunOnboard_UnknownMethod(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runOnboard([]string{
		"--method=mystery",
		"--court=did:test",
	}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("unknown method exit code = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "unknown --method") {
		t.Errorf("stderr should mention unknown method: %s", errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "hardcoded-genesis") {
		t.Errorf("stderr should list accepted modes: %s", errBuf.String())
	}
}

func TestRunOnboard_HappyPath_StdoutCertificate(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := runOnboard([]string{
		"--method=hardcoded-genesis",
		"--court=did:web:courts.davidson.example",
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("happy path exit code = %d, want 0 (stderr=%s)", code, errBuf.String())
	}
	// stdout contains the JSON encoding + a Summary line.
	stdout := out.String()
	if !strings.Contains(stdout, "did:web:courts.davidson.example") {
		t.Errorf("stdout missing court DID: %s", stdout)
	}
	if !strings.Contains(stdout, "method=hardcoded-genesis") {
		t.Errorf("stdout missing Summary line: %s", stdout)
	}
	// First line should be parseable as JSON.
	firstLine := strings.SplitN(stdout, "\n", 2)[0]
	var cert map[string]any
	if err := json.Unmarshal([]byte(firstLine), &cert); err != nil {
		t.Fatalf("first stdout line not JSON: %v\n%s", err, firstLine)
	}
}

func TestRunOnboard_OutFlag_WritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.json")
	var stdout, errBuf bytes.Buffer
	code := runOnboard([]string{
		"--method=anchor-log-sync",
		"--court=did:web:courts.williamson.example",
		"--out=" + path,
	}, &stdout, &errBuf)
	if code != 0 {
		t.Fatalf("--out exit code = %d (stderr=%s)", code, errBuf.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read --out: %v", err)
	}
	var cert map[string]any
	if err := json.Unmarshal(raw, &cert); err != nil {
		t.Fatalf("--out file not JSON: %v\n%s", err, string(raw))
	}
	// Summary still goes to stdout even when --out is set.
	if !strings.Contains(stdout.String(), "method=anchor-log-sync") {
		t.Errorf("stdout summary missing: %s", stdout.String())
	}
}

func TestOnboardUsage_MentionsAllModes(t *testing.T) {
	u := onboardUsage()
	for _, mode := range []string{"hardcoded-genesis", "anchor-log-sync", "trust-on-first-use"} {
		if !strings.Contains(u, mode) {
			t.Errorf("usage banner missing %q: %s", mode, u)
		}
	}
}
