/*
FILE PATH: schemas/role_catalog_alias.go

DESCRIPTION:

	Re-exports the role-catalog MECHANISM — extracted to libs/auth/policy
	as part of PRE-13a #104 — under the schemas names JN already used.
	These are type aliases / value re-exports, NOT re-implementations: the
	one home for RoleCatalog/InMemoryCatalog/ValidateGrant/ValidateRole is
	libs/auth/policy. The judicial role CONTENT (deployments/tn/...) and the
	file loader (role_catalog_loader.go) stay JN-side and inject content via
	NewInMemoryCatalog.
*/
package schemas

import libpolicy "github.com/baseproof/tooling/libs/auth/policy"

// Role is the platform catalog-row shape (the MECHANISM); judicial role
// CONTENT lives in this package's deployments and the loader.
type Role = libpolicy.Role

// RoleCatalog is the read-side interface (Lookup, List, ValidateGrant).
type RoleCatalog = libpolicy.RoleCatalog

// InMemoryCatalog is the default RoleCatalog implementation.
type InMemoryCatalog = libpolicy.InMemoryCatalog

// NewInMemoryCatalog builds a catalog from injected role content.
var NewInMemoryCatalog = libpolicy.NewInMemoryCatalog

// ErrRoleNotFound is returned for unknown role names.
var ErrRoleNotFound = libpolicy.ErrRoleNotFound
