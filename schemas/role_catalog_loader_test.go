/*
FILE PATH: schemas/role_catalog_loader_test.go

DESCRIPTION:
    Tests for the JSON-backed catalog loader: file load, in-memory
    parse, extended-duration syntax, hot-reload semantics. SIGHUP
    integration is exercised by manual ReloadFromFile rather than
    raising the actual signal — the watcher loop is a thin wrapper
    over ReloadFromFile.
*/
package schemas

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleCatalog = `{
  "roles": [
    {
      "name": "chief_justice",
      "description": "top of chain",
      "max_duration": "8y",
      "default_duration": "4y",
      "allowed_scope": ["case_filing", "invite:judge", "revoke:any"],
      "default_scope":  ["case_filing", "invite:judge", "revoke:any"],
      "delegable_scope": ["case_filing", "invite:judge", "revoke:any"]
    },
    {
      "name": "judge",
      "max_duration": "8760h",
      "default_duration": "30d",
      "allowed_scope": ["case_filing"],
      "default_scope":  ["case_filing"],
      "delegable_by":   ["chief_justice"],
      "delegable_scope": ["case_filing"]
    }
  ]
}`

func TestParseCatalogJSON_HappyPath(t *testing.T) {
	c, err := ParseCatalogJSON([]byte(sampleCatalog))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	cj, err := c.Lookup("chief_justice")
	if err != nil {
		t.Fatalf("lookup chief_justice: %v", err)
	}
	if cj.MaxDuration != 8*365*24*time.Hour {
		t.Errorf("8y expected %v, got %v", 8*365*24*time.Hour, cj.MaxDuration)
	}

	j, err := c.Lookup("judge")
	if err != nil {
		t.Fatalf("lookup judge: %v", err)
	}
	if j.MaxDuration != 8760*time.Hour {
		t.Errorf("8760h expected %v, got %v", 8760*time.Hour, j.MaxDuration)
	}
	if j.DefaultDuration != 30*24*time.Hour {
		t.Errorf("30d expected %v, got %v", 30*24*time.Hour, j.DefaultDuration)
	}
}

func TestParseCatalogJSON_NumericDuration(t *testing.T) {
	const numeric = `{"roles":[{
		"name":"x",
		"max_duration": 3600000000000,
		"default_duration": 3600000000000,
		"allowed_scope":["a"],
		"default_scope":["a"]
	}]}`
	c, err := ParseCatalogJSON([]byte(numeric))
	if err != nil {
		t.Fatalf("numeric duration parse: %v", err)
	}
	r, _ := c.Lookup("x")
	if r.MaxDuration != time.Hour {
		t.Errorf("expected 1h, got %v", r.MaxDuration)
	}
}

func TestParseCatalogJSON_MalformedJSON(t *testing.T) {
	_, err := ParseCatalogJSON([]byte("{not valid"))
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestParseCatalogJSON_MalformedDuration(t *testing.T) {
	const bad = `{"roles":[{
		"name":"x",
		"max_duration": "blarg",
		"default_duration": "1h",
		"allowed_scope":["a"],
		"default_scope":["a"]
	}]}`
	_, err := ParseCatalogJSON([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "duration") {
		t.Fatalf("expected duration parse error, got: %v", err)
	}
}

func TestParseCatalogJSON_RejectsInvalidRole(t *testing.T) {
	const bad = `{"roles":[{
		"name":"x",
		"max_duration":"1h",
		"default_duration":"2h",
		"allowed_scope":["a"],
		"default_scope":["a"]
	}]}`
	_, err := ParseCatalogJSON([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "exceeds max_duration") {
		t.Fatalf("expected role-validation error, got: %v", err)
	}
}

func TestLoadCatalogFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(path, []byte(sampleCatalog), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c, err := LoadCatalogFile(path)
	if err != nil {
		t.Fatalf("LoadCatalogFile: %v", err)
	}
	if _, err := c.Lookup("judge"); err != nil {
		t.Errorf("judge missing after load: %v", err)
	}
}

func TestLoadCatalogFile_MissingFile(t *testing.T) {
	_, err := LoadCatalogFile("/nonexistent/path/catalog.json")
	if err == nil {
		t.Fatal("expected file error")
	}
}

func TestReloadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(path, []byte(sampleCatalog), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c, err := LoadCatalogFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	pre := len(c.List())

	// Replace with a single-role catalog.
	const single = `{"roles":[{
		"name":"only",
		"max_duration":"1h",
		"default_duration":"1h",
		"allowed_scope":["a"],
		"default_scope":["a"]
	}]}`
	if err := os.WriteFile(path, []byte(single), 0o600); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	if err := c.ReloadFromFile(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	post := c.List()
	if len(post) == pre {
		t.Errorf("catalog did not shrink: still has %d roles", len(post))
	}
	if _, err := c.Lookup("only"); err != nil {
		t.Errorf("'only' missing: %v", err)
	}
}

func TestReloadFromFile_FailureKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(path, []byte(sampleCatalog), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := LoadCatalogFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Stomp file with invalid content.
	if err := os.WriteFile(path, []byte("not valid"), 0o600); err != nil {
		t.Fatalf("stomp: %v", err)
	}
	if err := c.ReloadFromFile(path); err == nil {
		t.Fatal("expected reload error")
	}

	// Previous catalog must still be in effect.
	if _, err := c.Lookup("judge"); err != nil {
		t.Errorf("previous catalog lost: %v", err)
	}
}

func TestParseExtendedDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"1h", time.Hour},
		{"30m", 30 * time.Minute},
		{"5d", 5 * 24 * time.Hour},
		{"2y", 2 * 365 * 24 * time.Hour},
	}
	for _, tc := range cases {
		got, err := parseExtendedDuration(tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %v want %v", tc.in, got, tc.want)
		}
	}
}
