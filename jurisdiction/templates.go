/*
FILE PATH: jurisdiction/templates.go

DESCRIPTION:

	EntryTemplate — the THIRD leg of the deployment tripod, next to the
	cosignature mix and the prerequisite policy. Those two already say who must
	sign an event and in what order — facing the verifier (they REJECT). A
	template adds the one thing that lives only in walkthrough prose today: the
	authoring shape — WHO signs first (the authority inversion no cosig rule
	captures, because the cosig rule only constrains cosigners), the payload's
	required fields + closed enums, and which case-local IDs it mints or cites.

	With all three, Compose (compose.go) authors an entry from the SAME policies
	the SubmitGate validates against — one source of truth, two directions, so an
	authored entry structurally cannot drift from what the gate accepts.

	A Bundle exposes its templates by implementing the OPTIONAL TemplateProvider
	interface. It is optional (not a Bundle method) so the ~7 existing Bundle
	implementations keep compiling; a bundle opts in when it wants composition,
	and Validate (bundle.go) then asserts template↔cosignature parity for it.
*/
package jurisdiction

import (
	"fmt"
	"sort"
)

// EntryTemplate is the per-event authoring shape. Values come from the caller
// (scenario input); the template owns structure (required fields, closed enums)
// and the authority inversion (PrimaryRole).
type EntryTemplate struct {
	// EventType is the snake_case event identifier; must match a
	// cosignature/prerequisite vocabulary entry. Required, unique.
	EventType string

	// SchemaURI is a documentation hint for the payload's domain shape
	// (e.g. "tn-counsel-appearance-v1"); "" ⇒ a generic payload. The
	// ledger ignores it; it rides into EntrySpec.Schema.
	SchemaURI string

	// PrimaryRole is the catalog role that signs FIRST (Signatures[0]).
	// This is the authority inversion: on an attorney filing the CLERK
	// signs first (Path A on the case root) while the attorney FILES —
	// no cosignature rule captures that, because it only constrains
	// cosigners. Values: a Signer role ("court_clerk", "judge",
	// "court_reporter", ...).
	PrimaryRole string

	// Mints names the case-local ID this event creates, or "" if none
	// (e.g. "binding_id" for counsel_appearance, "opinion_id" for an
	// appellate opinion). Forward-looking: consumed by reference
	// resolution as the case-context scanner lands.
	Mints string

	// References are the case-local IDs the payload must cite (e.g. a
	// binding_id a represented filing points back to). Forward-looking.
	References []string

	// Skeleton builds the event's payload fields MINUS the capacity
	// blocks (Compose weaves filed_by_capacity / signed_by_capacities
	// from the cosignature rule + cast). It returns a map so Compose can
	// merge the woven blocks before marshalling. Required fields + closed
	// enums live here; VALUES come from the caller via v.
	Skeleton func(cc *CaseContext, v Values) (map[string]any, error)
}

// TemplateSet is a jurisdiction's closed set of EntryTemplates, keyed by
// event_type. Immutable after construction.
type TemplateSet struct {
	byEvent map[string]EntryTemplate
}

// NewTemplateSet builds a TemplateSet, rejecting empty or duplicate event
// types and templates with no skeleton.
func NewTemplateSet(templates ...EntryTemplate) (TemplateSet, error) {
	byEvent := make(map[string]EntryTemplate, len(templates))
	for _, t := range templates {
		if t.EventType == "" {
			return TemplateSet{}, fmt.Errorf("jurisdiction: template with empty event_type")
		}
		if _, dup := byEvent[t.EventType]; dup {
			return TemplateSet{}, fmt.Errorf("jurisdiction: duplicate template event_type %q", t.EventType)
		}
		if t.Skeleton == nil {
			return TemplateSet{}, fmt.Errorf("jurisdiction: template %q has nil Skeleton", t.EventType)
		}
		byEvent[t.EventType] = t
	}
	return TemplateSet{byEvent: byEvent}, nil
}

// MustTemplateSet is NewTemplateSet or panic — for boot-time deployment
// registries (mirrors MustCosignaturePolicy / MustPrerequisitePolicy).
func MustTemplateSet(templates ...EntryTemplate) TemplateSet {
	s, err := NewTemplateSet(templates...)
	if err != nil {
		panic(fmt.Sprintf("jurisdiction: template set invalid: %v", err))
	}
	return s
}

// Lookup returns the template for event, and whether it exists.
func (s TemplateSet) Lookup(event string) (EntryTemplate, bool) {
	t, ok := s.byEvent[event]
	return t, ok
}

// EventTypes returns the known event types in sorted order.
func (s TemplateSet) EventTypes() []string {
	out := make([]string, 0, len(s.byEvent))
	for e := range s.byEvent {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// Len is the number of templates.
func (s TemplateSet) Len() int { return len(s.byEvent) }

// TemplateProvider is the OPTIONAL surface a Bundle implements to expose its
// authoring templates. Compose requires it; Validate checks template↔cosig
// parity for bundles that implement it.
type TemplateProvider interface {
	EntryTemplates() TemplateSet
}
