/*
FILE PATH: policy/cosignature_mix_loader_test.go

DESCRIPTION:
    Tests for the JSON-backed cosignature-mix policy loader:
    ParseJSON, LoadFile, ReloadFromFile (atomic-on-error), and the
    handling of malformed input.
*/
package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const samplePolicyJSON = `{
  "rules": [
    {
      "event_type": "motion_continuance",
      "allowed_filer_roles": ["defense_counsel", "civil_attorney"],
      "required_signer_roles": ["court_clerk", "judge"],
      "min_signer_cosigners": 1,
      "intra_exchange_only": true,
      "required_credentials": ["bpr_number"]
    },
    {
      "event_type": "verdict",
      "required_signer_roles": ["judge"],
      "intra_exchange_only": true
    },
    {
      "event_type": "case_transfer_outbound",
      "required_signer_roles": ["court_clerk", "judge"],
      "min_signer_cosigners": 1,
      "intra_exchange_only": false
    }
  ]
}`

// ─── ParseJSON ─────────────────────────────────────────────────────

func TestParseJSON_HappyPath(t *testing.T) {
	p, err := ParseJSON([]byte(samplePolicyJSON))
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	if got := len(p.List()); got != 3 {
		t.Errorf("rule count: got %d, want 3", got)
	}
	r, _ := p.Lookup("motion_continuance")
	if len(r.AllowedFilerRoles) != 2 {
		t.Errorf("motion AllowedFilerRoles: %v", r.AllowedFilerRoles)
	}
	if !r.IntraExchangeOnly {
		t.Error("motion should be intra-exchange-only")
	}
	transfer, _ := p.Lookup("case_transfer_outbound")
	if transfer.IntraExchangeOnly {
		t.Error("case_transfer_outbound must be cross-exchange permitted (Flag #2)")
	}
	verdict, _ := p.Lookup("verdict")
	if verdict.RequiresFiler() {
		t.Error("verdict must not require a filer")
	}
}

func TestParseJSON_MalformedJSON(t *testing.T) {
	_, err := ParseJSON([]byte("{not valid"))
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestParseJSON_RejectsInvalidRule(t *testing.T) {
	const bad = `{
      "rules": [
        {"event_type": ""}
      ]
    }`
	_, err := ParseJSON([]byte(bad))
	if !errors.Is(err, ErrInvalidRule) {
		t.Errorf("expected ErrInvalidRule, got: %v", err)
	}
}

func TestParseJSON_RejectsDuplicates(t *testing.T) {
	const dup = `{
      "rules": [
        {"event_type": "verdict", "required_signer_roles": ["judge"]},
        {"event_type": "verdict", "required_signer_roles": ["judge"]}
      ]
    }`
	_, err := ParseJSON([]byte(dup))
	if !errors.Is(err, ErrDuplicateRule) {
		t.Errorf("expected ErrDuplicateRule, got: %v", err)
	}
}

func TestParseJSON_RejectsUnknownFilerRole(t *testing.T) {
	const bad = `{
      "rules": [
        {
          "event_type": "x",
          "allowed_filer_roles": ["wizard"],
          "required_signer_roles": ["judge"]
        }
      ]
    }`
	_, err := ParseJSON([]byte(bad))
	if !errors.Is(err, ErrInvalidRule) {
		t.Errorf("expected ErrInvalidRule, got: %v", err)
	}
	if !strings.Contains(err.Error(), "FilerRole closed set") {
		t.Errorf("err should mention FilerRole closed set: %v", err)
	}
}

// ─── LoadFile ──────────────────────────────────────────────────────

func TestLoadFile_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(samplePolicyJSON), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	p, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if _, err := p.Lookup("verdict"); err != nil {
		t.Errorf("verdict missing after load: %v", err)
	}
}

func TestLoadFile_MissingFile(t *testing.T) {
	_, err := LoadFile("/nonexistent/policy.json")
	if err == nil {
		t.Fatal("expected file error")
	}
}

// ─── ReloadFromFile ────────────────────────────────────────────────

func TestReloadFromFile_AtomicReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(samplePolicyJSON), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	p, err := LoadFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	pre := len(p.List())

	// Replace with a single-rule policy.
	const single = `{"rules":[{
		"event_type": "only",
		"required_signer_roles": ["judge"]
	}]}`
	if err := os.WriteFile(path, []byte(single), 0o600); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	if err := p.ReloadFromFile(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	post := p.List()
	if len(post) >= pre {
		t.Errorf("expected shrink: pre=%d post=%d", pre, len(post))
	}
	if _, err := p.Lookup("only"); err != nil {
		t.Errorf("'only' missing: %v", err)
	}
}

func TestReloadFromFile_FailureKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(samplePolicyJSON), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	p, err := LoadFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Stomp file with invalid content.
	if err := os.WriteFile(path, []byte("not valid"), 0o600); err != nil {
		t.Fatalf("stomp: %v", err)
	}
	if err := p.ReloadFromFile(path); err == nil {
		t.Fatal("expected reload error")
	}

	// Previous policy must still be in effect.
	if _, err := p.Lookup("verdict"); err != nil {
		t.Errorf("previous policy lost: %v", err)
	}
}

func TestReloadFromFile_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(samplePolicyJSON), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	p, _ := LoadFile(path)

	if err := p.ReloadFromFile("/nonexistent/x.json"); err == nil {
		t.Fatal("expected file error")
	}
	// Original policy must still be in effect.
	if _, err := p.Lookup("verdict"); err != nil {
		t.Errorf("previous policy lost: %v", err)
	}
}

// ─── round-trip JSON ──────────────────────────────────────────────

func TestParseJSON_RoundTripPreservesAllFields(t *testing.T) {
	p, err := ParseJSON([]byte(samplePolicyJSON))
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	r, _ := p.Lookup("motion_continuance")
	if len(r.RequiredCredentials) != 1 || r.RequiredCredentials[0] != "bpr_number" {
		t.Errorf("required_credentials drift: %v", r.RequiredCredentials)
	}
	if r.MinSignerCosigners != 1 {
		t.Errorf("min_signer_cosigners: %d", r.MinSignerCosigners)
	}
	if !r.IntraExchangeOnly {
		t.Error("intra_exchange_only must be true")
	}
}
