/*
FILE PATH: verification/catalog_onehome_test.go

DESCRIPTION:

	#104 one-home import-guard. The role-catalog MECHANISM was extracted to
	tooling/libs/auth/policy (RoleCatalog / InMemoryCatalog / ValidateGrant +
	helpers); JN now only ALIASES it (schemas/role_catalog_alias.go: type X = ...).
	This default-on test fails CI if any JN file re-DECLARES the mechanism
	(a fresh struct/interface/func, not an alias) — i.e. if the dedup the
	extraction removed tries to regrow.
*/
package verification

import (
	"go/ast"
	"go/token"
	"testing"
)

func TestCensus_CatalogMechanismOnlyInLibsAuth(t *testing.T) {
	root := jnModuleRoot(t)
	forbiddenTypes := map[string]bool{"RoleCatalog": true, "InMemoryCatalog": true}
	forbiddenFuncs := map[string]bool{"ValidateGrant": true, "validateRole": true, "roleAllowedToDelegate": true}

	walkProdGoFiles(t, root, func(rel string, f *ast.File, _ *token.FileSet) {
		ast.Inspect(f, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.TypeSpec:
				// `type X = Y` (alias, Assign set) is fine; a fresh declaration is not.
				if d.Assign == token.NoPos && forbiddenTypes[d.Name.Name] {
					switch d.Type.(type) {
					case *ast.StructType, *ast.InterfaceType:
						t.Errorf("%s: re-declares type %s — the role-catalog mechanism's one home is "+
							"libs/auth/policy; JN may only alias it (type %s = policy.%s).",
							rel, d.Name.Name, d.Name.Name, d.Name.Name)
					}
				}
			case *ast.FuncDecl:
				if forbiddenFuncs[d.Name.Name] {
					t.Errorf("%s: re-implements %s — the role-catalog mechanism's one home is libs/auth/policy.",
						rel, d.Name.Name)
				}
			}
			return true
		})
	})
}
