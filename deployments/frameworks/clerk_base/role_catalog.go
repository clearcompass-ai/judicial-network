/*
FILE PATH: deployments/frameworks/clerk_base/role_catalog.go

DESCRIPTION:

	The clerk-office role catalog: the 6-level pyramid every clerk
	office (TN County Clerk, TN Circuit Court Clerk, CA Court
	Executive Officer, federal District Court Clerk) shares.

	# The pyramid

	    Level 1: Executive Clerk
	    Level 2: Chief Deputy Clerk
	    Level 3: Branch Manager / Department Supervisor
	    Level 4: Senior Deputy Clerk
	    Level 5: Frontline Deputy Clerk
	    Level 6: File / Records Clerk

	# Reusability

	Every state's clerk offices use this same role catalog. State
	conventions add state-specific role variants via the NameFmt
	field on ClerkSlot, but the underlying role categories are
	identical across states.
*/
package clerk_base

import (
	"time"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// Role names the catalog publishes. Stable across releases.
const (
	RoleExecutiveClerk       = "executive_clerk"
	RoleChiefDeputyClerk     = "chief_deputy_clerk"
	RoleBranchManager        = "branch_manager"
	RoleSeniorDeputyClerk    = "senior_deputy_clerk"
	RoleFrontlineDeputyClerk = "frontline_deputy_clerk"
	RoleFileRecordsClerk     = "file_records_clerk"
)

// Scope tokens the catalog publishes for clerk-office delegations.
const (
	ScopeIssueCertification  = "issue:certification" // issue official certifications
	ScopeOpenFiling          = "open:filing"         // accept and stamp new filings
	ScopeIssueLicense        = "issue:license"       // marriage/business/vehicle licenses
	ScopeIssueIDDocument     = "issue:id_document"   // driver's licenses, Real IDs
	ScopeCollectFee          = "collect:fee"         // accept payments at the counter
	ScopeRouteDocument       = "route:document"      // move records between offices
	ScopeManageBranch        = "manage:branch"       // branch-level operational
	ScopeInviteDeputy        = "invite:deputy"       // bring on a new deputy
	ScopeInviteSeniorDeputy  = "invite:senior_deputy"
	ScopeInviteBranchManager = "invite:branch_manager"
	ScopeInviteChiefDeputy   = "invite:chief_deputy"
)

// MustRoleCatalog returns the shared clerk-office role catalog.
// Panics if catalog construction fails — boot-time failure is loud.
func MustRoleCatalog() schemas.RoleCatalog {
	catalog, err := schemas.NewInMemoryCatalog(catalogRoles())
	if err != nil {
		panic("clerk_base: role catalog: " + err.Error())
	}
	return catalog
}

func catalogRoles() []schemas.Role {
	// Durations chosen pragmatically: executive deputization is
	// long-lived (multi-year terms); frontline deputization is
	// per-shift (8h default, 24h max). All deputizations are
	// revocable; these are upper bounds on how long an
	// unrevoked delegation may stand.
	const (
		execMax      = 8 * 365 * 24 * time.Hour // 8 years
		execDefault  = 4 * 365 * 24 * time.Hour // 4 years
		chiefMax     = 4 * 365 * 24 * time.Hour // 4 years
		chiefDefault = 1 * 365 * 24 * time.Hour // 1 year
		mgrMax       = 1 * 365 * 24 * time.Hour // 1 year
		mgrDefault   = 90 * 24 * time.Hour      // 90 days
		seniorMax    = 90 * 24 * time.Hour      // 90 days
		seniorDef    = 30 * 24 * time.Hour      // 30 days
		frontMax     = 24 * time.Hour           // 24h
		frontDef     = 8 * time.Hour            // 8h
		fileMax      = 24 * time.Hour           // 24h
		fileDef      = 8 * time.Hour            // 8h
	)
	return []schemas.Role{
		{
			Name:        RoleExecutiveClerk,
			Actor:       schemas.ActorSigner,
			Description: "Elected or appointed head of a clerk office (TN County/Circuit/Criminal Court Clerks, TN Clerk and Master, CA Court Executive Officer, federal Clerk of Court).",
			MaxDuration: execMax, DefaultDuration: execDefault,
			AllowedScope: []string{
				ScopeIssueCertification, ScopeOpenFiling, ScopeIssueLicense,
				ScopeIssueIDDocument, ScopeCollectFee, ScopeRouteDocument,
				ScopeManageBranch, ScopeInviteDeputy, ScopeInviteSeniorDeputy,
				ScopeInviteBranchManager, ScopeInviteChiefDeputy,
			},
			DefaultScope: []string{
				ScopeIssueCertification, ScopeOpenFiling, ScopeIssueLicense,
				ScopeIssueIDDocument, ScopeCollectFee, ScopeManageBranch,
				ScopeInviteChiefDeputy, ScopeInviteBranchManager,
			},
			DelegableBy:    nil, // instituted directly by the institutional DID
			DelegableScope: nil, // no constraint on what they can pass down
		},
		{
			Name:        RoleChiefDeputyClerk,
			Actor:       schemas.ActorSigner,
			Description: "Chief operating officer of the clerk office. Supervises Branch Managers and department heads.",
			MaxDuration: chiefMax, DefaultDuration: chiefDefault,
			AllowedScope: []string{
				ScopeIssueCertification, ScopeOpenFiling, ScopeIssueLicense,
				ScopeIssueIDDocument, ScopeCollectFee, ScopeRouteDocument,
				ScopeManageBranch, ScopeInviteDeputy, ScopeInviteSeniorDeputy,
				ScopeInviteBranchManager,
			},
			DefaultScope: []string{
				ScopeIssueCertification, ScopeOpenFiling, ScopeManageBranch,
				ScopeInviteBranchManager,
			},
			DelegableBy: []string{RoleExecutiveClerk},
			DelegableScope: []string{
				ScopeIssueCertification, ScopeOpenFiling, ScopeIssueLicense,
				ScopeIssueIDDocument, ScopeCollectFee, ScopeRouteDocument,
				ScopeManageBranch, ScopeInviteDeputy, ScopeInviteSeniorDeputy,
				ScopeInviteBranchManager,
			},
		},
		{
			Name:        RoleBranchManager,
			Actor:       schemas.ActorSigner,
			Description: "Supervises a physical satellite office or department.",
			MaxDuration: mgrMax, DefaultDuration: mgrDefault,
			AllowedScope: []string{
				ScopeIssueCertification, ScopeOpenFiling, ScopeIssueLicense,
				ScopeIssueIDDocument, ScopeCollectFee, ScopeRouteDocument,
				ScopeInviteDeputy, ScopeInviteSeniorDeputy,
			},
			DefaultScope: []string{
				ScopeOpenFiling, ScopeIssueLicense, ScopeCollectFee,
				ScopeInviteDeputy,
			},
			DelegableBy: []string{RoleExecutiveClerk, RoleChiefDeputyClerk},
			DelegableScope: []string{
				ScopeOpenFiling, ScopeIssueLicense, ScopeIssueIDDocument,
				ScopeCollectFee, ScopeRouteDocument, ScopeInviteDeputy,
				ScopeInviteSeniorDeputy,
			},
		},
		{
			Name:        RoleSeniorDeputyClerk,
			Actor:       schemas.ActorSigner,
			Description: "Veteran clerk handling complex transactions (titles, fleet registrations, Real ID).",
			MaxDuration: seniorMax, DefaultDuration: seniorDef,
			AllowedScope: []string{
				ScopeOpenFiling, ScopeIssueLicense, ScopeIssueIDDocument,
				ScopeCollectFee, ScopeRouteDocument, ScopeInviteDeputy,
			},
			DefaultScope: []string{
				ScopeOpenFiling, ScopeIssueLicense, ScopeIssueIDDocument,
				ScopeCollectFee,
			},
			DelegableBy: []string{
				RoleExecutiveClerk, RoleChiefDeputyClerk, RoleBranchManager,
			},
			DelegableScope: []string{
				ScopeOpenFiling, ScopeIssueLicense, ScopeIssueIDDocument,
				ScopeCollectFee, ScopeRouteDocument, ScopeInviteDeputy,
			},
		},
		{
			Name:        RoleFrontlineDeputyClerk,
			Actor:       schemas.ActorSigner,
			Description: "Core counter workforce. Issues licenses, processes registrations, intakes filings.",
			MaxDuration: frontMax, DefaultDuration: frontDef,
			AllowedScope: []string{
				ScopeOpenFiling, ScopeIssueLicense, ScopeIssueIDDocument,
				ScopeCollectFee, ScopeRouteDocument,
			},
			DefaultScope: []string{
				ScopeOpenFiling, ScopeIssueLicense, ScopeCollectFee,
			},
			DelegableBy: []string{
				RoleExecutiveClerk, RoleChiefDeputyClerk, RoleBranchManager,
				RoleSeniorDeputyClerk,
			},
			DelegableScope: []string{
				ScopeOpenFiling, ScopeIssueLicense, ScopeIssueIDDocument,
				ScopeCollectFee, ScopeRouteDocument,
			},
		},
		{
			Name:        RoleFileRecordsClerk,
			Actor:       schemas.ActorSigner,
			Description: "Records archivist. Routes documents, scans files. Does NOT issue certifications.",
			MaxDuration: fileMax, DefaultDuration: fileDef,
			AllowedScope: []string{ScopeRouteDocument},
			DefaultScope: []string{ScopeRouteDocument},
			DelegableBy: []string{
				RoleExecutiveClerk, RoleChiefDeputyClerk, RoleBranchManager,
			},
			DelegableScope: []string{ScopeRouteDocument},
		},
	}
}
