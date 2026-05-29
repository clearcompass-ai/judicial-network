/*
FILE PATH: deployments/registry/loader.go

DESCRIPTION:

	The registry is the SINGLE source-of-truth list of every court
	the JN supports. It's data, not code: each state contributes one
	file (tn.go, ca.go, fed.go) returning a []composer.Spec, and the
	loader stitches them together at boot.

	Adding a new state = adding one file + one entry in the loader's
	state list. Adding a new court within a covered state = adding one
	Spec to that state's file. The framework code never changes.

	# Why a Go-data registry, not YAML/JSON

	The Spec struct embeds Credential interface values — type-safe
	references to credential implementations. YAML would need a
	parallel name-to-Credential resolver layer; Go data is
	directly-linked and type-checked at compile time. New states can
	contribute new credentials in the same compilation unit, so a CA
	bundle binding an unknown TN credential fails to compile, not at
	runtime.

	# How main_helpers.go consumes the registry

	cmd/network-api/main_helpers.go calls registry.LoadAll(); the
	returned []jurisdiction.Bundle is registered into the JN's
	jurisdiction.Registry one-by-one. No per-state import + Register
	loop in main; the registry IS the loop.
*/
package registry

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/composer"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// AllSpecs returns the union of every state's courts. The order is
// stable (federal, then states alphabetically within each tier) so
// audit-trail outputs are reproducible.
func AllSpecs() []composer.Spec {
	var specs []composer.Spec
	specs = append(specs, FederalSpecs()...)
	specs = append(specs, TennesseeSpecs()...)
	specs = append(specs, CaliforniaSpecs()...)
	return specs
}

// LoadAll reduces every Spec in AllSpecs to a jurisdiction.Bundle and
// returns the result. Panics if any Spec is invalid — boot-time
// configuration errors MUST surface at process start.
func LoadAll() []jurisdiction.Bundle {
	specs := AllSpecs()
	bundles := make([]jurisdiction.Bundle, 0, len(specs))
	seen := make(map[string]string, len(specs))
	for _, spec := range specs {
		if other, dup := seen[spec.DID]; dup {
			panic(fmt.Sprintf(
				"registry: duplicate DID %q (%s and %s) — registry entries must be unique",
				spec.DID, other, spec.Name))
		}
		seen[spec.DID] = spec.Name
		bundles = append(bundles, composer.Build(spec))
	}
	return bundles
}

// LoadInto registers every Bundle returned by LoadAll into the
// supplied jurisdiction.Registry. Returns the first registration
// error encountered (registry duplicate or validation failure).
//
// This is the canonical entry point cmd/network-api/main_helpers.go
// calls in place of the per-package Register loop.
func LoadInto(r *jurisdiction.Registry) error {
	for _, b := range LoadAll() {
		if err := r.Register(b); err != nil {
			return fmt.Errorf("registry: register %s: %w", b.ExchangeDID(), err)
		}
	}
	return nil
}
