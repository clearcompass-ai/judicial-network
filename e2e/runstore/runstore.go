// Package runstore is the reusable .run/{id} state store for the baseproof e2e
// stack.
//
// A run is a named config bundle keyed by a 3-char id. Everything a stack needs —
// mTLS material, identity keys, per-network bootstrap, and the persisted stack
// manifest — lives together under {root}/{id}/, so the same id can be brought up,
// torn down, and brought up again reusing identical keys/DIDs. The manifest is what
// `status`/`run`/`wipe` read to find and address the live stack. $E2E_RUN_ROOT
// relocates the root (default ./.run).
package runstore

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const idAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// Root is the .run root: $E2E_RUN_ROOT or ./.run, resolved to an ABSOLUTE path
// (docker bind-mounts reject relative host paths — they read them as named-volume
// names).
//
// When E2E_RUN_ROOT is unset, Root walks UP from the working directory to find an
// existing .run directory. This is load-bearing for `go test`: a test binary runs
// with its CWD set to the test PACKAGE dir (e.g. e2e/tests/jn), so a bare ./.run
// would miss the run `e2e up` created at the repo root and every scenario would
// skip on an empty config. Walking up resolves the SAME run from anywhere in the
// tree. When no .run exists yet (first `e2e up`), it falls back to ./.run so the
// run is created under the current dir as before.
func Root() string {
	if r := os.Getenv("E2E_RUN_ROOT"); r != "" {
		if abs, err := filepath.Abs(r); err == nil {
			return abs
		}
		return r
	}
	if wd, err := os.Getwd(); err == nil {
		for dir := wd; ; {
			cand := filepath.Join(dir, ".run")
			if fi, statErr := os.Stat(cand); statErr == nil && fi.IsDir() {
				return cand
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break // reached the filesystem root
			}
			dir = parent
		}
	}
	if abs, err := filepath.Abs(".run"); err == nil {
		return abs
	}
	return ".run"
}

// ValidID reports whether s is exactly 3 alphanumeric characters.
func ValidID(s string) bool {
	if len(s) != 3 {
		return false
	}
	for _, c := range s {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// GenID mints a fresh lowercase 3-char id.
func GenID() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	out := make([]byte, 3)
	for i, x := range b {
		out[i] = idAlphabet[int(x)%len(idAlphabet)]
	}
	return string(out)
}

// Layout is the on-disk layout of one run under {root}/{id}.
type Layout struct {
	ID         string
	Home       string
	Certs      string
	Fixtures   string
	Identities string
	Diag       string
}

// New builds a Layout under the default Root().
func New(id string) (*Layout, error) { return NewUnder(Root(), id) }

// NewUnder builds a Layout under an explicit root (used by tests).
func NewUnder(root, id string) (*Layout, error) {
	if !ValidID(id) {
		return nil, fmt.Errorf("invalid run id %q — need 3 alphanumeric chars", id)
	}
	home := filepath.Join(root, id)
	return &Layout{
		ID:         id,
		Home:       home,
		Certs:      filepath.Join(home, "certs"),
		Fixtures:   filepath.Join(home, "fixtures"),
		Identities: filepath.Join(home, "identities"),
		Diag:       filepath.Join(home, "diag"),
	}, nil
}

// Mkdirs creates the run's directory tree.
func (l *Layout) Mkdirs() error {
	for _, d := range []string{l.Home, l.Certs, l.Fixtures, l.Identities, l.Diag} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func (l *Layout) manifestPath() string { return filepath.Join(l.Home, "stack.json") }

// Manifest is the persisted record of a brought-up stack.
type Manifest struct {
	ID        string            `json:"id"`
	Preset    string            `json:"preset"`
	Network   string            `json:"network"`   // docker network name
	Admission string            `json:"admission"` // credits|pow (how the runner drives workloads)
	Networks  []NetworkManifest `json:"networks"`
}

// NetworkManifest is one network's externally-addressable surface — the complete
// set of host ports/names a runner recipe (or the env-bridge to the moved suites)
// needs to reach the network without re-deriving the spec.
type NetworkManifest struct {
	Name           string `json:"name"`
	LogDID         string `json:"log_did"`
	QuorumK        int    `json:"quorum_k"`
	LedgerName     string `json:"ledger_name"`
	LedgerPort     int    `json:"ledger_port"`
	ReaderPort     int    `json:"reader_port,omitempty"` // PG-off read front; 0/omitted when not launched
	JNPort         int    `json:"jn_port,omitempty"`
	AggregatorPort int    `json:"aggregator_port,omitempty"`
	AuditorPorts   []int  `json:"auditor_ports,omitempty"`
}

// SaveManifest persists the stack manifest.
func (l *Layout) SaveManifest(m *Manifest) error {
	if err := l.Mkdirs(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(l.manifestPath(), append(b, '\n'), 0o644)
}

// LoadManifest reads the persisted stack manifest.
func (l *Layout) LoadManifest() (*Manifest, error) {
	b, err := os.ReadFile(l.manifestPath())
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// IsProvisioned reports whether this run holds a persisted manifest (a stack was
// brought up and not wiped).
func (l *Layout) IsProvisioned() bool {
	_, err := os.Stat(l.manifestPath())
	return err == nil
}

// Remove deletes the entire run directory (wipe).
func (l *Layout) Remove() error { return os.RemoveAll(l.Home) }

// ListRuns returns existing run ids under root, oldest→newest by mtime.
func ListRuns(root string) []string {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	type r struct {
		id string
		mt int64
	}
	var runs []r
	for _, e := range ents {
		if e.IsDir() && ValidID(e.Name()) {
			mt := int64(0)
			if info, err := e.Info(); err == nil {
				mt = info.ModTime().UnixNano()
			}
			runs = append(runs, r{e.Name(), mt})
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].mt < runs[j].mt })
	out := make([]string, len(runs))
	for i, x := range runs {
		out[i] = x.id
	}
	return out
}

// ResolveID resolves the run id to operate on: an explicit id wins; otherwise the
// latest existing run; otherwise (when !mustExist) a freshly minted id.
func ResolveID(requested, root string, mustExist bool) (string, error) {
	if requested != "" {
		if !ValidID(requested) {
			return "", fmt.Errorf("invalid run id %q — need 3 alphanumeric chars", requested)
		}
		return requested, nil
	}
	if runs := ListRuns(root); len(runs) > 0 {
		return runs[len(runs)-1], nil
	}
	if mustExist {
		return "", fmt.Errorf("no runs under %s — bring one up first", root)
	}
	return GenID(), nil
}
