/*
Package openapi embeds the OpenAPI 3.1 spec and exposes it as an
embed.FS so the api/ composer can serve it from a single binary.

The canonical artifact is api/openapi/openapi.yaml. Tests in
spec_test.go assert the spec parses, declares OpenAPI 3.1.0, and
documents every route currently registered by the composer.
*/
package openapi

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var specYAML []byte

// Spec returns the embedded OpenAPI 3.1 YAML bytes. Callers MUST
// treat the returned slice as read-only.
func Spec() []byte { return specYAML }

// Handler returns an http.Handler that serves the spec as
// application/yaml at whatever path the caller mounts it under.
// The composer mounts this at /v1/openapi.yaml so external tooling
// (Swagger UI, code generators) can fetch the canonical artifact.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(specYAML)
	})
}
