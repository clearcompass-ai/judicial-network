/*
FILE PATH: netmanifest/manifest.go

DESCRIPTION:

	The network consumption manifest — the DESCRIBE projection of a
	jurisdiction.Bundle, served at GET /v1/network/bundle and published on-log
	as an entry citing the manifest anchor schema (the same SchemaRef pattern
	the admission keyset uses).

	One policy source, three projections: the SubmitGate VALIDATES against
	CosignaturePolicy + PrerequisitePolicy; a composer AUTHORS from them; this
	package SERIALIZES them — so the served contract structurally cannot drift
	from what the gate enforces. The wire shape EMBEDS the enforced types
	verbatim (policy.CosignatureRule, prereq.Prereq — both already JSON-tagged)
	rather than re-modeling them.

	Naming: "bundle" is taken throughout the ecosystem (protocol.NetworkBundle,
	jurisdiction.Bundle, the SDK's log/bundle proof artifact, the CLI's
	ClientBundle), so this package is netmanifest and the document a Manifest;
	only the ENDPOINT path keeps the /v1/network/bundle name, slotting into the
	/v1/network/* discovery family the SDK's log/discover clients consume.
*/
package netmanifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	prereq "github.com/baseproof/tooling/libs/prereq"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/policy"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// Format tags the wire document so a reader rejects an unknown vintage.
const Format = "baseproof-network-manifest/v1"

// Manifest is the served + on-log document: how to consume ONE exchange on ONE
// network. Wire types use slices (never maps) so CanonicalBytes is
// deterministic.
type Manifest struct {
	Format   string     `json:"format"`
	Network  NetworkRef `json:"network"`
	Exchange string     `json:"exchange"` // the jurisdiction (registry key) this manifest describes

	Endpoints []Endpoint `json:"endpoints,omitempty"`
	Admission Admission  `json:"admission"`

	// Submit + Status are uniform for every operation on this network: where a
	// write goes in, and how any instance's state is probed.
	Submit Submit       `json:"submit"`
	Status StatusProbes `json:"status"`

	Roles      []schemas.Role `json:"roles,omitempty"`
	Datatypes  []Datatype     `json:"datatypes,omitempty"`
	Operations []Operation    `json:"operations"`
}

// NetworkRef names the network by REFERENCE — identity + the genesis pin.
// Trust material is NOT embedded: a consumer fetches the bootstrap from
// BootstrapEndpoint and verifies it against BootstrapHash (the established
// content-address + TOFU pattern).
type NetworkRef struct {
	NetworkID         string `json:"network_id,omitempty"` // 64-hex
	Name              string `json:"name,omitempty"`
	BootstrapHash     string `json:"bootstrap_hash,omitempty"` // 64-hex sha256 of canonical bootstrap
	BootstrapEndpoint string `json:"bootstrap_endpoint,omitempty"`
	QuorumK           int    `json:"quorum_k,omitempty"`
}

// Endpoint is one service surface of the network, with its status probe and
// the endpoints it depends on (the deployment DAG).
type Endpoint struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Protocol  string    `json:"protocol,omitempty"`
	Transport Transport `json:"transport"`
	Status    string    `json:"status,omitempty"` // probe path, e.g. /healthz
	DependsOn []string  `json:"depends_on,omitempty"`
}

// Transport is the TLS posture a caller needs to reach an endpoint.
type Transport struct {
	TLS   string `json:"tls"`              // "server-verify" | "mtls" | "plaintext"
	CAPin string `json:"ca_pin,omitempty"` // optional 64-hex sha256 of the CA cert
}

// Admission states the two write-admission axes explicitly. Derived from boot
// state, never asserted: WriteVia is "gate" iff the gate mints
// WriteAuthorizations; Payment lists the modes the forward actually supports.
type Admission struct {
	Payment     []string `json:"payment,omitempty"` // "credit", "pow"
	Gating      string   `json:"gating,omitempty"`  // "write-authorization" | "open"
	WriteVia    string   `json:"write_via"`         // endpoint ID writes go through
	PolicyProbe string   `json:"policy_probe,omitempty"`
}

// Submit is where a write enters the network.
type Submit struct {
	Endpoint string `json:"endpoint"` // endpoint ID
	Path     string `json:"path"`     // e.g. /v1/entries/submit
}

// StatusProbes names how state is read, uniformly for every operation:
// protocol state (accepted → sequenced) at Protocol, finality at Finality
// (cosigned horizon ≥ seq), and DOMAIN state by the amendment-chain rule —
// an instance's status is the terminal entry of its closed_by/amended_by
// chain.
type StatusProbes struct {
	Protocol string `json:"protocol"` // e.g. ledger:/v1/entries-hash/{hash}
	Finality string `json:"finality"` // e.g. ledger:/v1/tree/horizon
	Domain   string `json:"domain"`
}

// Datatype is a payload vocabulary entry, referenced verifiably: by URI and —
// when published — by on-log position + content hash.
type Datatype struct {
	Name        string `json:"name"`
	URI         string `json:"uri,omitempty"`
	LogDID      string `json:"log_did,omitempty"`
	Sequence    uint64 `json:"sequence,omitempty"`
	ContentHash string `json:"content_hash,omitempty"`
}

// Operation is one node of the operation DAG. Signing and Requires EMBED the
// enforced policy types verbatim — the same structs the SubmitGate checks —
// so describe and validate share one source. The overlay fields carry the
// authoring knowledge that exists nowhere else (primary signer, datatype,
// minted/cited identifiers, lifecycle edges).
type Operation struct {
	EventType string `json:"event_type"`

	// Kind: "origin" when no Hard RequiredAncestor rule orders this operation
	// after another (it may still be authority-gated); "dependent" otherwise.
	Kind string `json:"kind"`

	// Signing is the enforced cosignature mix (nil ⇒ no cosignature rule — a
	// bootstrap/vocabulary-only event the gate admits on prerequisites alone).
	Signing *policy.CosignatureRule `json:"signing,omitempty"`

	// Requires are the enforced admission-order edges (hard/advisory;
	// RequiredAncestor lists carry OR semantics).
	Requires []prereq.Prereq `json:"requires,omitempty"`

	// Overlay (authoring knowledge; optional).
	PrimaryRole string   `json:"primary_role,omitempty"`
	Datatype    string   `json:"datatype,omitempty"`
	Mints       []string `json:"mints,omitempty"`
	References  []string `json:"references,omitempty"`
	ClosedBy    []string `json:"closed_by,omitempty"` // lifecycle: events that close/amend an instance
}

// OpOverlay is the per-event authoring overlay a deployment supplies (the
// knowledge the policies don't carry: who signs first, what shape, what it
// mints, what closes it).
type OpOverlay struct {
	PrimaryRole string
	Datatype    string
	Mints       []string
	References  []string
	ClosedBy    []string
}

// BuildInput carries everything outside the jurisdiction.Bundle: network
// identity by reference, the endpoint inventory, admission posture, probes,
// and the optional overlay.
type BuildInput struct {
	Network   NetworkRef
	Endpoints []Endpoint
	Admission Admission
	Submit    Submit
	Status    StatusProbes
	Overlay   map[string]OpOverlay
	Datatypes []Datatype
}

// Build projects a jurisdiction.Bundle into its Manifest. The operation set is
// the prerequisite policy's closed-set vocabulary (the superset —
// jurisdiction.Validate guarantees every cosignature event is in it).
func Build(b jurisdiction.Bundle, in BuildInput) (*Manifest, error) {
	if b == nil {
		return nil, errors.New("netmanifest: nil bundle")
	}
	if err := jurisdiction.Validate(b); err != nil {
		return nil, fmt.Errorf("netmanifest: %w", err)
	}

	cat := b.RoleCatalog()
	roleNames := append([]string(nil), cat.List()...)
	sort.Strings(roleNames)
	roles := make([]schemas.Role, 0, len(roleNames))
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

	ops := make([]Operation, 0, len(events))
	for _, evt := range events {
		rules, err := pp.Lookup(evt)
		if err != nil {
			return nil, fmt.Errorf("netmanifest: prereq lookup %q: %w", evt, err)
		}
		op := Operation{EventType: evt, Kind: kindOf(rules), Requires: rules}
		if rule, lErr := cosig.Lookup(evt); lErr == nil {
			op.Signing = rule
		} else if !errors.Is(lErr, policy.ErrRuleNotFound) {
			return nil, fmt.Errorf("netmanifest: cosig lookup %q: %w", evt, lErr)
		}
		if ov, ok := in.Overlay[evt]; ok {
			op.PrimaryRole = ov.PrimaryRole
			op.Datatype = ov.Datatype
			op.Mints = append([]string(nil), ov.Mints...)
			op.References = append([]string(nil), ov.References...)
			op.ClosedBy = append([]string(nil), ov.ClosedBy...)
		}
		ops = append(ops, op)
	}

	m := &Manifest{
		Format:     Format,
		Network:    in.Network,
		Exchange:   b.ExchangeDID(),
		Endpoints:  in.Endpoints,
		Admission:  in.Admission,
		Submit:     in.Submit,
		Status:     in.Status,
		Roles:      roles,
		Datatypes:  in.Datatypes,
		Operations: ops,
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// kindOf classifies an operation: "dependent" when any Hard RequiredAncestor
// rule orders it after another operation; "origin" otherwise (authority-gated
// events with no log-order dependency are origins of the DAG).
func kindOf(rules []prereq.Prereq) string {
	for i := range rules {
		if rules[i].Mode == prereq.PrereqModeHard && rules[i].IsAncestorRule() {
			return "dependent"
		}
	}
	return "origin"
}

// Validate checks the manifest's internal structure:
//
//   - format tag, exchange, and per-operation event types are non-empty;
//     operation event types are unique;
//   - every overlay edge (ClosedBy / References) targets an operation IN the
//     manifest — a lifecycle edge to an unknown event is authoring drift;
//   - endpoint DependsOn edges and Submit.Endpoint resolve to declared
//     endpoint IDs (when any endpoints are declared);
//   - the UNAMBIGUOUS-hard-edge subgraph is acyclic: an edge evt→anc exists
//     when a Hard rule names exactly ONE ancestor. OR-alternative lists are
//     excluded from the cycle check (an OR edge is not an unconditional
//     dependency), so a legitimate either-or policy never false-positives.
func (m *Manifest) Validate() error {
	if m.Format != Format {
		return fmt.Errorf("netmanifest: format %q, want %q", m.Format, Format)
	}
	if m.Exchange == "" {
		return errors.New("netmanifest: exchange is required")
	}
	known := make(map[string]bool, len(m.Operations))
	for i := range m.Operations {
		evt := m.Operations[i].EventType
		if evt == "" {
			return fmt.Errorf("netmanifest: operations[%d] has empty event_type", i)
		}
		if known[evt] {
			return fmt.Errorf("netmanifest: duplicate operation %q", evt)
		}
		known[evt] = true
	}
	for i := range m.Operations {
		op := &m.Operations[i]
		for _, t := range op.ClosedBy {
			if !known[t] {
				return fmt.Errorf("netmanifest: %s closed_by %q: not an operation in this manifest", op.EventType, t)
			}
		}
		for _, t := range op.References {
			if !known[t] {
				return fmt.Errorf("netmanifest: %s references %q: not an operation in this manifest", op.EventType, t)
			}
		}
	}
	if len(m.Endpoints) > 0 {
		eps := make(map[string]bool, len(m.Endpoints))
		for i := range m.Endpoints {
			if m.Endpoints[i].ID == "" || m.Endpoints[i].URL == "" {
				return fmt.Errorf("netmanifest: endpoints[%d] needs id + url", i)
			}
			if eps[m.Endpoints[i].ID] {
				return fmt.Errorf("netmanifest: duplicate endpoint id %q", m.Endpoints[i].ID)
			}
			eps[m.Endpoints[i].ID] = true
		}
		for i := range m.Endpoints {
			for _, d := range m.Endpoints[i].DependsOn {
				if !eps[d] {
					return fmt.Errorf("netmanifest: endpoint %q depends_on unknown %q", m.Endpoints[i].ID, d)
				}
			}
		}
		if m.Submit.Endpoint != "" && !eps[m.Submit.Endpoint] {
			return fmt.Errorf("netmanifest: submit.endpoint %q not a declared endpoint", m.Submit.Endpoint)
		}
	}
	if cycle := findHardCycle(m.Operations); len(cycle) > 0 {
		return fmt.Errorf("netmanifest: hard-prerequisite cycle: %v", cycle)
	}
	return nil
}

// findHardCycle DFS-checks the unambiguous hard-edge subgraph (single-ancestor
// Hard rules between in-manifest operations). Returns a witness path or nil.
func findHardCycle(ops []Operation) []string {
	edges := make(map[string][]string, len(ops))
	in := make(map[string]bool, len(ops))
	for i := range ops {
		in[ops[i].EventType] = true
	}
	for i := range ops {
		for _, r := range ops[i].Requires {
			if r.Mode == prereq.PrereqModeHard && len(r.RequiredAncestor) == 1 && in[r.RequiredAncestor[0]] {
				edges[ops[i].EventType] = append(edges[ops[i].EventType], r.RequiredAncestor[0])
			}
		}
	}
	const (
		white = 0
		grey  = 1
		black = 2
	)
	color := make(map[string]int, len(ops))
	var stack []string
	var visit func(string) []string
	visit = func(n string) []string {
		color[n] = grey
		stack = append(stack, n)
		for _, next := range edges[n] {
			switch color[next] {
			case grey:
				return append(stack, next) // cycle witness
			case white:
				if c := visit(next); c != nil {
					return c
				}
			}
		}
		color[n] = black
		stack = stack[:len(stack)-1]
		return nil
	}
	for i := range ops {
		if color[ops[i].EventType] == white {
			if c := visit(ops[i].EventType); c != nil {
				return c
			}
		}
	}
	return nil
}

// TopoOrder returns the operations in a dependency-respecting order (origins
// first), using the same unambiguous hard edges as the cycle check; ties
// resolve alphabetically so the order is deterministic. A scenario driver
// (emulator) submits in this order.
func (m *Manifest) TopoOrder() []string {
	in := make(map[string]bool, len(m.Operations))
	for i := range m.Operations {
		in[m.Operations[i].EventType] = true
	}
	deps := make(map[string]map[string]bool, len(m.Operations))
	for i := range m.Operations {
		evt := m.Operations[i].EventType
		deps[evt] = map[string]bool{}
		for _, r := range m.Operations[i].Requires {
			if r.Mode == prereq.PrereqModeHard && len(r.RequiredAncestor) == 1 && in[r.RequiredAncestor[0]] {
				deps[evt][r.RequiredAncestor[0]] = true
			}
		}
	}
	out := make([]string, 0, len(deps))
	done := make(map[string]bool, len(deps))
	for len(out) < len(deps) {
		progressed := false
		var ready []string
		for evt, d := range deps {
			if done[evt] {
				continue
			}
			ok := true
			for anc := range d {
				if !done[anc] {
					ok = false
					break
				}
			}
			if ok {
				ready = append(ready, evt)
			}
		}
		sort.Strings(ready)
		for _, evt := range ready {
			done[evt] = true
			out = append(out, evt)
			progressed = true
		}
		if !progressed { // cycle residue: append the rest deterministically
			var rest []string
			for evt := range deps {
				if !done[evt] {
					rest = append(rest, evt)
				}
			}
			sort.Strings(rest)
			return append(out, rest...)
		}
	}
	return out
}

// DependentsOf returns the operations that transitively REQUIRE evt over Hard
// ancestor edges (OR-alternatives included here — any rule NAMING evt makes
// the dependent's status sensitive to it). This is the monitoring cascade: an
// instance of evt changing domain status is relevant to every returned
// operation.
func (m *Manifest) DependentsOf(evt string) []string {
	rev := make(map[string][]string)
	for i := range m.Operations {
		for _, r := range m.Operations[i].Requires {
			if r.Mode != prereq.PrereqModeHard {
				continue
			}
			for _, anc := range r.RequiredAncestor {
				rev[anc] = append(rev[anc], m.Operations[i].EventType)
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	var walk func(string)
	walk = func(n string) {
		for _, d := range rev[n] {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
				walk(d)
			}
		}
	}
	walk(evt)
	sort.Strings(out)
	return out
}

// CanonicalBytes is the deterministic wire form (struct-ordered JSON; the wire
// types use slices, never maps). The on-log entry payload and the served body
// are exactly these bytes; ContentHash is their sha256.
func (m *Manifest) CanonicalBytes() ([]byte, error) {
	return json.Marshal(m)
}

// ContentHash is sha256(CanonicalBytes) — the pin a consumer verifies the
// served document against (ETag) and the on-log payload hash.
func (m *Manifest) ContentHash() ([32]byte, error) {
	b, err := m.CanonicalBytes()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// Decode parses + validates a wire manifest (strict: unknown fields rejected,
// so a reader can't silently misread a future vintage).
func Decode(data []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("netmanifest: decode: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}
