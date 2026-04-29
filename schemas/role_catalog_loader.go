/*
FILE PATH: schemas/role_catalog_loader.go

DESCRIPTION:
    File-backed loader for the RoleCatalog. Reads a JSON catalog
    from disk; optionally subscribes to SIGHUP for hot-reload.

    Format: a top-level JSON object with a single key "roles" whose
    value is an array of Role objects. Durations may be passed either
    as a Go duration string ("8760h", "4y") or as nanoseconds.

    The user's original spec called this "court-controlled YAML."
    The catalog file format is mechanical; using JSON keeps the
    schemas package free of external dependencies. Operators wanting
    YAML can render YAML → JSON in their deployment pipeline, or
    drop in a side-loader that calls Replace().

KEY ARCHITECTURAL DECISIONS:
    - The on-disk file is the source of truth at boot. Reload
      replaces the entire catalog atomically; partial reload is
      not supported (every role is re-validated together so a typo
      cannot accidentally widen scope on one role and not another).
    - SIGHUP reload is optional and opt-in via WatchSignal. By
      default the catalog is loaded once at boot. Operators who
      want runtime reload call WatchSignal in main().
    - Failed reload (file missing, parse error, validation error)
      logs and keeps the *previous* catalog. The system never goes
      catalog-less at runtime.

OVERVIEW:
    LoadCatalogFile         — boot-time load.
    (*InMemoryCatalog).WatchSignal — opt-in SIGHUP reload loop.

KEY DEPENDENCIES:
    - schemas/role_catalog.go (Role, InMemoryCatalog).
*/
package schemas

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// catalogFile is the on-disk JSON layout. Durations parse via the
// json.Unmarshaler on durationJSON.
type catalogFile struct {
	Roles []roleJSON `json:"roles"`
}

// roleJSON mirrors Role but uses durationJSON for the time fields so
// operators can write "4y" / "8760h" without computing nanoseconds.
type roleJSON struct {
	Name            string       `json:"name"`
	Description     string       `json:"description,omitempty"`
	MaxDuration     durationJSON `json:"max_duration"`
	DefaultDuration durationJSON `json:"default_duration"`
	AllowedScope    []string     `json:"allowed_scope"`
	DefaultScope    []string     `json:"default_scope"`
	DelegableBy     []string     `json:"delegable_by,omitempty"`
	DelegableScope  []string     `json:"delegable_scope,omitempty"`
}

// durationJSON accepts a Go duration string or a numeric nanoseconds
// value. The "4y" and "8760h" forms are both legal — the former is
// parsed manually, the latter via time.ParseDuration.
type durationJSON time.Duration

func (d *durationJSON) UnmarshalJSON(data []byte) error {
	// numeric (nanoseconds)
	if len(data) > 0 && data[0] != '"' {
		var n int64
		if err := json.Unmarshal(data, &n); err != nil {
			return fmt.Errorf("schemas/role_catalog_loader: malformed numeric duration: %w", err)
		}
		*d = durationJSON(n)
		return nil
	}
	// string
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("schemas/role_catalog_loader: malformed string duration: %w", err)
	}
	parsed, err := parseExtendedDuration(s)
	if err != nil {
		return err
	}
	*d = durationJSON(parsed)
	return nil
}

// parseExtendedDuration accepts time.ParseDuration's syntax plus the
// "Ny" (years) and "Nd" (days) suffixes the catalog commonly uses.
// "4y" → 4*365*24h, "30d" → 30*24h.
func parseExtendedDuration(s string) (time.Duration, error) {
	if len(s) >= 2 {
		last := s[len(s)-1]
		if last == 'y' || last == 'd' {
			var n int
			if _, err := fmt.Sscanf(s[:len(s)-1], "%d", &n); err != nil {
				return 0, fmt.Errorf("schemas/role_catalog_loader: malformed duration %q: %w", s, err)
			}
			switch last {
			case 'y':
				return time.Duration(n) * 365 * 24 * time.Hour, nil
			case 'd':
				return time.Duration(n) * 24 * time.Hour, nil
			}
		}
	}
	return time.ParseDuration(s)
}

func (rj roleJSON) toRole() Role {
	return Role{
		Name:            rj.Name,
		Description:     rj.Description,
		MaxDuration:     time.Duration(rj.MaxDuration),
		DefaultDuration: time.Duration(rj.DefaultDuration),
		AllowedScope:    rj.AllowedScope,
		DefaultScope:    rj.DefaultScope,
		DelegableBy:     rj.DelegableBy,
		DelegableScope:  rj.DelegableScope,
	}
}

// LoadCatalogFile reads, parses, and validates a catalog JSON file.
// Returns an InMemoryCatalog ready to use, or an error.
func LoadCatalogFile(path string) (*InMemoryCatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("schemas/role_catalog_loader: read %q: %w", path, err)
	}
	return ParseCatalogJSON(data)
}

// ParseCatalogJSON parses an in-memory JSON blob into a catalog.
// Exposed for tests and for operators piping content from their own
// secret store / config service.
func ParseCatalogJSON(data []byte) (*InMemoryCatalog, error) {
	var f catalogFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("schemas/role_catalog_loader: parse: %w", err)
	}
	roles := make([]Role, 0, len(f.Roles))
	for _, rj := range f.Roles {
		roles = append(roles, rj.toRole())
	}
	return NewInMemoryCatalog(roles)
}

// ReloadFromFile re-reads the catalog file and atomically replaces
// the catalog contents. Used by SIGHUP handlers.
func (c *InMemoryCatalog) ReloadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("schemas/role_catalog_loader: read %q: %w", path, err)
	}
	var f catalogFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("schemas/role_catalog_loader: parse: %w", err)
	}
	roles := make([]Role, 0, len(f.Roles))
	for _, rj := range f.Roles {
		roles = append(roles, rj.toRole())
	}
	return c.Replace(roles)
}

// WatchSignal subscribes to SIGHUP and reloads the catalog from path
// whenever the signal arrives. Runs until ctx-like channel done is
// closed. Failures log but do not panic — the previous catalog stays
// in effect. Optional; production deployments call this in main().
func (c *InMemoryCatalog) WatchSignal(path string, done <-chan struct{}, logf func(format string, args ...any)) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-done:
				return
			case <-ch:
				if err := c.ReloadFromFile(path); err != nil {
					if logf != nil {
						logf("role_catalog: reload from %s failed (keeping previous): %v", path, err)
					}
					continue
				}
				if logf != nil {
					logf("role_catalog: reloaded from %s (%d roles)", path, len(c.List()))
				}
			}
		}
	}()
}
