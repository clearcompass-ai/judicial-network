/*
FILE PATH: netmanifest/manifest.go

DESCRIPTION:

	The jurisdiction PROJECTOR — the judicial half of the network bundle.
	The wire schema (Manifest, Operation, Validate, canonical bytes, the
	graph mechanics, strict decode) lives in the platform's
	libs/networkbundle; THIS package projects a compiled
	jurisdiction.Bundle into that schema, so the served contract
	structurally cannot drift from what the SubmitGate enforces: the gate
	validates against CosignaturePolicy + PrerequisitePolicy, and Build
	serializes the SAME rule values verbatim.

	JN2 (the composer line): every overlay-named datatype is guaranteed a
	Datatypes[] row — missing rows are synthesized (Name-only) so the
	schema's structural rule (an operation's datatype must be DECLARED)
	holds at Build() time, loudly. The on-log ANCHOR fields
	({log_did, sequence, content_hash}) are deployment configuration
	supplied through BuildInput.Datatypes once published — the consumer
	door (networkbundle.VerifyManifest) refuses driveable operations
	without them, which is the planned alarm until publication. The
	JN2-before-D1 ordering note lives here on purpose: the CLI's manifest
	importer must never meet a JN manifest whose driveable ops lack
	anchors.
*/
package netmanifest

import (
	"errors"
	"fmt"
	"sort"

	"github.com/baseproof/tooling/libs/networkbundle"
	"github.com/baseproof/tooling/libs/auth/policy"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// Build projects a jurisdiction.Bundle into its Manifest. The operation set is
// the prerequisite policy's closed-set vocabulary (the superset —
// jurisdiction.Validate guarantees every cosignature event is in it).
func Build(b jurisdiction.Bundle, in networkbundle.BuildInput) (*networkbundle.Manifest, error) {
	if b == nil {
		return nil, errors.New("netmanifest: nil bundle")
	}
	if err := jurisdiction.Validate(b); err != nil {
		return nil, fmt.Errorf("netmanifest: %w", err)
	}

	cat := b.RoleCatalog()
	roleNames := append([]string(nil), cat.List()...)
	sort.Strings(roleNames)
	roles := make([]policy.Role, 0, len(roleNames))
	for _, n := range roleNames {
		r, err := cat.Lookup(n)
		if err != nil {
			return nil, fmt.Errorf("netmanifest: role %q: %w", n, err)
		}
		roles = append(roles, r)
	}

	cosig := b.CosignaturePolicy()
	pp := b.PrerequisitePolicy()
	events := append([]string(nil), pp.EventTypes()...)
	sort.Strings(events)

	ops := make([]networkbundle.Operation, 0, len(events))
	for _, evt := range events {
		rules, err := pp.Lookup(evt)
		if err != nil {
			return nil, fmt.Errorf("netmanifest: prereq lookup %q: %w", evt, err)
		}
		var signing *policy.CosignatureRule
		if rule, lErr := cosig.Lookup(evt); lErr == nil {
			signing = rule
		} else if !errors.Is(lErr, policy.ErrRuleNotFound) {
			return nil, fmt.Errorf("netmanifest: cosig lookup %q: %w", evt, lErr)
		}
		ops = append(ops, networkbundle.NewOperation(evt, signing, rules, in.Overlay[evt]))
	}

	m := &networkbundle.Manifest{
		Format:     networkbundle.ManifestFormat,
		Network:    in.Network,
		Exchange:   b.ExchangeDID(),
		Endpoints:  in.Endpoints,
		Admission:  in.Admission,
		Submit:     in.Submit,
		Status:     in.Status,
		Roles:      roles,
		Datatypes:  synthesizeDatatypes(in.Datatypes, ops),
		Operations: ops,
		Federation: in.Federation,
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// synthesizeDatatypes is the JN2 composer line: every datatype an operation
// names gets a declared row. Supplied rows (with anchors, once published)
// pass through untouched; missing ones are synthesized Name-only — valid
// structurally, refused by the consumer door until anchored, which is the
// planned publication alarm.
func synthesizeDatatypes(supplied []networkbundle.Datatype, ops []networkbundle.Operation) []networkbundle.Datatype {
	out := append([]networkbundle.Datatype(nil), supplied...)
	declared := make(map[string]bool, len(out))
	for i := range out {
		declared[out[i].Name] = true
	}
	var missing []string
	seen := make(map[string]bool)
	for i := range ops {
		dt := ops[i].Datatype
		if dt != "" && !declared[dt] && !seen[dt] {
			seen[dt] = true
			missing = append(missing, dt)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		out = append(out, networkbundle.Datatype{Name: name})
	}
	return out
}
