/*
FILE PATH: cmd/network-api/auditor_loaders.go

DESCRIPTION:

	File-based loaders for the v1.33.x auditor-scope gate inputs:

	  - loadAuditorRegistry  → network.AuditorRegistrationByPosition
	  - loadAuditorAmendments → network.AuditorScopeAmendmentByPosition

	Both shapes mirror the attesta-tools auditor service
	(services/auditor/internal/app/auditor_registry.go +
	auditor_amendments.go), so one operator manifest drives both auditor
	AND JN with byte-identical inputs. The JSON shape is the on-log
	record (EffectivePos + Payload + Checkpoint), NOT the wire payload.

	Sort discipline: both loaders enforce strictly-ascending EffectivePos.
	An unsorted file is a config bug (the resolver assumes monotonic
	position order to walk records linearly), so we boot-fail loudly
	rather than silently re-sorting.
*/
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/baseproof/baseproof/network"
)

// loadAuditorRegistry reads a JSON file containing
// []network.AuditorRegistrationRecord and returns it as the typed
// position-sorted slice the reconciler consumes. Empty path returns
// (nil, nil) — that disables the scope gate (cfg.Validate enforces
// Enforce=true requires a non-empty path).
//
// Errors:
//   - file unreadable or not JSON → wrapped
//   - records present but unsorted (EffectivePos non-monotonic) → boot fail
func loadAuditorRegistry(path string) (network.AuditorRegistrationByPosition, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read auditor registry %s: %w", path, err)
	}
	var records []network.AuditorRegistrationRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("parse auditor registry %s: %w", path, err)
	}
	for i := 1; i < len(records); i++ {
		prev := records[i-1].EffectivePos
		cur := records[i].EffectivePos
		if !prev.Less(cur) && !prev.Equal(cur) {
			return nil, fmt.Errorf("auditor registry %s: records unsorted at index %d (EffectivePos %s before %s)",
				path, i, prev, cur)
		}
	}
	return network.AuditorRegistrationByPosition(records), nil
}

// loadAuditorAmendments reads a JSON file containing
// []network.AuditorScopeAmendmentRecord. Empty path returns (nil, nil)
// — that is the legal "no amendments yet" state and keeps the
// registry-only scope. Same sort discipline as loadAuditorRegistry.
func loadAuditorAmendments(path string) (network.AuditorScopeAmendmentByPosition, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read auditor amendments %s: %w", path, err)
	}
	var records []network.AuditorScopeAmendmentRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("parse auditor amendments %s: %w", path, err)
	}
	for i := 1; i < len(records); i++ {
		prev := records[i-1].EffectivePos
		cur := records[i].EffectivePos
		if !prev.Less(cur) && !prev.Equal(cur) {
			return nil, fmt.Errorf("auditor amendments %s: records unsorted at index %d (EffectivePos %s before %s)",
				path, i, prev, cur)
		}
	}
	return network.AuditorScopeAmendmentByPosition(records), nil
}
