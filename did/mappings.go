/*
FILE PATH: did/mappings.go

DESCRIPTION:

	Vendor DID mappings for the judicial network. These were removed
	from the ortholog-sdk in v0.1.0 because they are domain-specific
	and have no business in the protocol-level SDK.

	Each mapping translates a judicial vendor DID method to did:web
	for resolution. The SDK's did.VendorDIDResolver consumes these
	mappings; this file declares them.

	Default transform (nil TransformFunc): reverses colon-separated
	parts, joins with dots, appends DomainSuffix.

	Examples:
	  did:court:tn            → did:web:tn.court.gov
	  did:court:tn:davidson   → did:web:davidson.tn.court.gov
	  did:jnet:tn:appellate   → did:web:appellate.tn.jnet.gov
	  did:ccr:agency:fbi-ncic → did:web:fbi-ncic.agency.ccr.org

KEY DEPENDENCIES:

  - ortholog-sdk/did: VendorMapping struct, NewVendorDIDResolver

    VendorMapping fields (verified from did/vendor_did.go):
    Method        string
    DomainSuffix  string
    TargetMethod  string
    TransformFunc func(specific string) (string, error)  // nil = default
*/
package judicialdid

import "github.com/clearcompass-ai/ortholog-sdk/did"

// CourtMapping maps did:court:<jurisdiction>[:<division>] to
// did:web:<reversed-parts>.court.gov.
func CourtMapping() did.VendorMapping {
	return did.VendorMapping{
		Method:       "court",
		DomainSuffix: ".court.gov",
		TargetMethod: "web",
	}
}

// JNetMapping maps did:jnet:<network>:<segment> to
// did:web:<reversed-parts>.jnet.gov.
func JNetMapping() did.VendorMapping {
	return did.VendorMapping{
		Method:       "jnet",
		DomainSuffix: ".jnet.gov",
		TargetMethod: "web",
	}
}

// CCRMapping maps did:ccr:<role>:<name> to
// did:web:<reversed-parts>.ccr.org.
func CCRMapping() did.VendorMapping {
	return did.VendorMapping{
		Method:       "ccr",
		DomainSuffix: ".ccr.org",
		TargetMethod: "web",
	}
}

// AllMappings returns all three judicial mappings for convenience.
// Usage:
//
//	resolver := did.NewVendorDIDResolver(base, judicialdid.AllMappings())
func AllMappings() []did.VendorMapping {
	return []did.VendorMapping{
		CourtMapping(),
		JNetMapping(),
		CCRMapping(),
	}
}
