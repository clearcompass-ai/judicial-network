/*
FILE PATH: deployments/frameworks/composer/clerk_build.go

DESCRIPTION:

	BuildClerk — reduces a ClerkSpec to a jurisdiction.Bundle. Mirror
	of composer.Build but pulls policies from frameworks/clerk_base
	instead of trial_base / appellate_base / supreme_base.

	A clerk-office Bundle structurally satisfies the SDK contract:
	role catalog (the 6-level pyramid), cosignature policy (clerk
	events), prerequisite policy (mostly empty today), authority
	chain resolver, empty appellate vocabulary.
*/
package composer

import (
	"fmt"

	"github.com/baseproof/tooling/libs/auth/policy"
	prerequisites "github.com/baseproof/tooling/libs/prereq"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/clerk_base"
	"github.com/clearcompass-ai/judicial-network/deployments/frameworks/credentials"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// ClerkSpec is the typed view this package exposes for clerks.
// county_profile.ClerkSpec is the source-of-truth; the composer
// re-declares the fields it consumes here so the composer doesn't
// import county_profile (avoiding cycles).
type ClerkSpec struct {
	DID                 string
	Name                string
	Jurisdiction        Jurisdiction
	RequiredCredentials []credentials.Credential
}

// BuildClerk reduces a ClerkSpec to a jurisdiction.Bundle. Panics on
// invalid spec — boot-time configuration errors fail loud.
func BuildClerk(spec ClerkSpec) jurisdiction.Bundle {
	if spec.DID == "" {
		panic("composer.BuildClerk: DID required")
	}
	if spec.Name == "" {
		panic("composer.BuildClerk: Name required")
	}
	courtJ := credentials.Jurisdiction{
		State:   spec.Jurisdiction.State,
		Federal: spec.Jurisdiction.Federal,
	}
	for _, c := range spec.RequiredCredentials {
		if err := credentials.CheckAcceptable(c, courtJ); err != nil {
			panic(fmt.Sprintf("composer.BuildClerk(%s): %v", spec.DID, err))
		}
	}

	b := &clerkBundle{
		did:     spec.DID,
		catalog: clerk_base.MustRoleCatalog(),
		cosig:   clerk_base.MustCosignaturePolicy(),
		preqs:   clerk_base.MustPrerequisitePolicy(),
		appVoc:  jurisdiction.EmptyAppellateVocab(),
	}
	if err := jurisdiction.Validate(b); err != nil {
		panic(fmt.Sprintf("composer.BuildClerk(%s): %v", spec.DID, err))
	}
	return b
}

type clerkBundle struct {
	did     string
	catalog schemas.RoleCatalog
	cosig   policy.CosignatureMixPolicy
	preqs   prerequisites.Policy
	appVoc  jurisdiction.AppellateVocab
}

func (b *clerkBundle) ExchangeDID() string                            { return b.did }
func (b *clerkBundle) RoleCatalog() schemas.RoleCatalog               { return b.catalog }
func (b *clerkBundle) CosignaturePolicy() policy.CosignatureMixPolicy { return b.cosig }
func (b *clerkBundle) PrerequisitePolicy() prerequisites.Policy       { return b.preqs }
func (b *clerkBundle) AppellateVocabulary() jurisdiction.AppellateVocab {
	return b.appVoc
}
func (b *clerkBundle) AuthorityChainResolver() jurisdiction.AuthorityChainResolver {
	return authorityChainResolver
}

var _ jurisdiction.Bundle = (*clerkBundle)(nil)
