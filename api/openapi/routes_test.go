/*
FILE PATH: api/openapi/routes_test.go

DESCRIPTION:

	Canonical (method, path) table of every route the composer's
	BuildHandler registers across api/judicial, api/exchange,
	api/verification, and the composer itself. Lives in its own file
	so spec_test.go stays focused on the validation harness.

	Drift detection: TestSpec_DocumentedPathsMatchRegisteredRoutes
	cross-checks this list against the spec. Any addition to the
	composer's mux MUST land here AND in openapi.yaml in the same
	change.
*/
package openapi

type routePattern struct {
	method string
	path   string
}

var registeredRoutes = []routePattern{
	// Composer
	{method: "GET", path: "/healthz"},
	{method: "GET", path: "/v1/openapi.yaml"},

	// Cases
	{method: "POST", path: "/v1/judicial/cases"},
	{method: "POST", path: "/v1/judicial/cases/{caseRootSeq}/amend"},
	{method: "POST", path: "/v1/judicial/cases/{caseRootSeq}/filings"},
	{method: "POST", path: "/v1/judicial/cases/{caseRootSeq}/actions"},
	{method: "GET", path: "/v1/judicial/cases/{docket}"},
	{method: "POST", path: "/v1/judicial/cases/{caseRootSeq}/transfer/division"},
	{method: "POST", path: "/v1/judicial/cases/{caseRootSeq}/transfer/county"},

	// Appeals
	{method: "POST", path: "/v1/judicial/appeals/decisions"},
	{method: "POST", path: "/v1/judicial/appeals/mandates/affirm"},
	{method: "POST", path: "/v1/judicial/appeals/initiations"},
	{method: "POST", path: "/v1/judicial/appeals/mandates/reverse"},
	{method: "POST", path: "/v1/judicial/appeals/records/transfer"},

	// Enforcement
	{method: "POST", path: "/v1/judicial/enforcement/seal"},
	{method: "POST", path: "/v1/judicial/enforcement/unseal"},
	{method: "POST", path: "/v1/judicial/enforcement/unseal/cosignature"},
	{method: "GET", path: "/v1/judicial/enforcement/sealing-status"},
	{method: "POST", path: "/v1/judicial/enforcement/expunge"},
	{method: "POST", path: "/v1/judicial/enforcement/evidence-access"},
	{method: "GET", path: "/v1/judicial/enforcement/compliance"},

	// Parties
	{method: "POST", path: "/v1/judicial/parties/bindings"},
	{method: "GET", path: "/v1/judicial/parties/bindings"},
	{method: "PATCH", path: "/v1/judicial/parties/bindings/{seq}/status"},
	{method: "POST", path: "/v1/judicial/parties/case-links"},
	{method: "POST", path: "/v1/judicial/parties/bindings/sealed"},
	{method: "GET", path: "/v1/judicial/parties/bindings/by-id/{bindingID}"},

	// Onboarding
	{method: "POST", path: "/v1/judicial/onboarding/schema-adoption"},
	{method: "POST", path: "/v1/judicial/onboarding/court-provision"},
	{method: "POST", path: "/v1/judicial/onboarding/anchor-registration"},
	{method: "POST", path: "/v1/judicial/onboarding/migrate-records"},

	// Artifacts (Judicial)
	{method: "POST", path: "/v1/judicial/artifacts"},
	{method: "GET", path: "/v1/judicial/artifacts/retrieve"},
	{method: "DELETE", path: "/v1/judicial/artifacts/{cid}"},
	{method: "POST", path: "/v1/judicial/artifacts/reencrypt"},

	// Verification
	{method: "GET", path: "/v1/judicial/verification/case-status"},
	{method: "GET", path: "/v1/judicial/verification/enforcement-status"},
	{method: "POST", path: "/v1/judicial/verification/filing-delegation"},
	{method: "GET", path: "/v1/judicial/verification/custody-chain"},
	{method: "GET", path: "/v1/judicial/verification/background-check"},
	{method: "POST", path: "/v1/judicial/verification/appeal-chain"},
	{method: "GET", path: "/v1/judicial/verification/key-attestation"},
	{method: "POST", path: "/v1/judicial/verification/cross-log-proof"},

	// Monitoring
	{method: "POST", path: "/v1/judicial/monitoring/blob-availability"},
	{method: "POST", path: "/v1/judicial/monitoring/delegation-health"},
	{method: "GET", path: "/v1/judicial/monitoring/anchor-freshness"},
	{method: "POST", path: "/v1/judicial/monitoring/dual-attestation"},
	{method: "POST", path: "/v1/judicial/monitoring/mirror-consistency"},
	{method: "POST", path: "/v1/judicial/monitoring/sealing-compliance"},
	{method: "POST", path: "/v1/judicial/monitoring/grant-compliance"},
	{method: "POST", path: "/v1/judicial/monitoring/dashboard"},

	// Consortium
	{method: "POST", path: "/v1/judicial/consortium/members/propose-addition"},
	{method: "POST", path: "/v1/judicial/consortium/members/propose-removal"},
	{method: "POST", path: "/v1/judicial/consortium/cross-court-proof/verify"},
	{method: "POST", path: "/v1/judicial/consortium/cross-court-proof/build"},
	{method: "POST", path: "/v1/judicial/consortium/members/execute-addition"},
	{method: "POST", path: "/v1/judicial/consortium/members/execute-removal"},
	{method: "POST", path: "/v1/judicial/consortium/members/activate-removal"},
	{method: "POST", path: "/v1/judicial/consortium/formation"},

	// Delegation (Judicial) + Topology
	{method: "POST", path: "/v1/judicial/delegation/issue"},
	{method: "POST", path: "/v1/judicial/delegation/revoke"},
	{method: "POST", path: "/v1/judicial/delegation/succeed"},
	{method: "POST", path: "/v1/judicial/topology/publish-anchor"},
	{method: "GET", path: "/v1/judicial/topology/anchor-chain"},

	// Escrow recovery
	{method: "POST", path: "/v1/judicial/escrow/recovery/initiate"},
	{method: "POST", path: "/v1/judicial/escrow/migration/record"},
	{method: "POST", path: "/v1/judicial/escrow/recovery/collect-share"},
	{method: "POST", path: "/v1/judicial/escrow/recovery/execute"},
	{method: "POST", path: "/v1/judicial/escrow/arbitration/evaluate"},

	// Stand-alone judicial healthz
	{method: "GET", path: "/v1/judicial/healthz"},

	// Generic Entries
	{method: "POST", path: "/v1/entries/build"},
	{method: "POST", path: "/v1/entries/sign"},
	{method: "POST", path: "/v1/entries/submit"},
	{method: "POST", path: "/v1/entries/build-sign-submit"},
	{method: "GET", path: "/v1/entries/status/{hash}"},

	// Generic Artifacts
	{method: "POST", path: "/v1/artifacts/publish"},
	{method: "POST", path: "/v1/artifacts/{cid}/grant"},

	// Generic Delegations
	{method: "POST", path: "/v1/delegations"},
	{method: "DELETE", path: "/v1/delegations/{did}"},

	// Keys
	{method: "POST", path: "/v1/keys/generate"},
	{method: "POST", path: "/v1/keys/rotate"},
	{method: "POST", path: "/v1/keys/escrow"},
	{method: "GET", path: "/v1/keys"},

	// DIDs
	{method: "POST", path: "/v1/dids"},
	{method: "GET", path: "/v1/dids"},

	// Scope
	{method: "POST", path: "/v1/scope/propose"},
	{method: "POST", path: "/v1/scope/approve/{pos}"},
	{method: "POST", path: "/v1/scope/execute/{pos}"},

	// Verify (api/verification)
	{method: "GET", path: "/v1/verify/origin/{logID}/{pos}"},
	{method: "GET", path: "/v1/verify/authority/{logID}/{pos}"},
	{method: "GET", path: "/v1/verify/batch/{logID}/{positions}"},
	{method: "GET", path: "/v1/verify/delegation/{logID}/{pos}"},
	{method: "GET", path: "/v1/verify/complete/{logID}/{pos}"},
	{method: "POST", path: "/v1/verify/cross-log"},
	{method: "POST", path: "/v1/verify/fraud-proof"},
}
