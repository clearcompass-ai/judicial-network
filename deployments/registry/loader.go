/*
FILE PATH: deployments/registry/loader.go

DESCRIPTION:

	The registry is the SINGLE source-of-truth list of every court
	+ clerk-office the JN supports. The data lives across state-
	specific files (tn.go + tn_counties.go, ca.go + ca_counties.go,
	fed.go); the loader composes them into bundles at boot.

	# Compose pipeline

	    [state-level Specs (Supreme, COA, federal Circuit/SCOTUS)]
	         +
	    [Expand(CountyProfile, state convention) →
	       court Specs + clerk Specs per county]
	         ↓
	    composer.Build(spec) / composer.BuildClerk(spec)
	         ↓
	    []jurisdiction.Bundle

	Adding a new TN county = one CountyProfile literal in tn_counties.go.
	Adding a new state = one tn.go + one tn_counties.go style pair plus
	a state_profile/<state>.go implementing Conventions.
	The loader and framework code don't change.
*/
package registry

import (
	"fmt"

	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/composer"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/county_profile"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/state_profile"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
)

// AllCourtSpecs returns every court Spec the registry exposes —
// state-level specs (TN Supreme, TN COA grand divisions, federal
// Circuit/SCOTUS, CA appellate hierarchy) PLUS every court Spec
// expanded from per-county CountyProfiles.
func AllCourtSpecs() []composer.Spec {
	var specs []composer.Spec
	specs = append(specs, FederalSpecs()...)
	specs = append(specs, TennesseeStateLevelSpecs()...)
	specs = append(specs, CaliforniaStateLevelSpecs()...)
	for _, county := range TennesseeCounties() {
		courts, _ := county_profile.Expand(county, state_profile.TN())
		specs = append(specs, courts...)
	}
	for _, county := range CaliforniaCounties() {
		courts, _ := county_profile.Expand(county, state_profile.CA())
		specs = append(specs, courts...)
	}
	return specs
}

// AllClerkSpecs returns every clerk Spec the registry exposes,
// expanded from per-county CountyProfiles via the state conventions.
// Federal clerks are listed alongside (in FederalClerkSpecs).
func AllClerkSpecs() []county_profile.ClerkSpec {
	var clerks []county_profile.ClerkSpec
	for _, county := range TennesseeCounties() {
		_, ct := county_profile.Expand(county, state_profile.TN())
		clerks = append(clerks, ct...)
	}
	for _, county := range CaliforniaCounties() {
		_, ca := county_profile.Expand(county, state_profile.CA())
		clerks = append(clerks, ca...)
	}
	return clerks
}

// LoadAll reduces every Spec + ClerkSpec in the registry to a
// jurisdiction.Bundle and returns the result. Panics on duplicate
// DIDs or invalid specs.
func LoadAll() []jurisdiction.Bundle {
	var bundles []jurisdiction.Bundle
	seen := make(map[string]string, 256)
	check := func(did, name string) {
		if other, dup := seen[did]; dup {
			panic(fmt.Sprintf(
				"registry: duplicate DID %q (%s and %s)",
				did, other, name))
		}
		seen[did] = name
	}
	for _, spec := range AllCourtSpecs() {
		check(spec.DID, spec.Name)
		bundles = append(bundles, composer.Build(spec))
	}
	for _, clerk := range AllClerkSpecs() {
		check(clerk.DID, clerk.Name)
		bundles = append(bundles, composer.BuildClerk(composer.ClerkSpec{
			DID:                 clerk.DID,
			Name:                clerk.Name,
			Jurisdiction:        clerk.Jurisdiction,
			RequiredCredentials: clerk.RequiredCredentials,
		}))
	}
	return bundles
}

// LoadInto registers every bundle into the supplied registry.
func LoadInto(r *jurisdiction.Registry) error {
	for _, b := range LoadAll() {
		if err := r.Register(b); err != nil {
			return fmt.Errorf("registry: register %s: %w", b.ExchangeDID(), err)
		}
	}
	return nil
}
