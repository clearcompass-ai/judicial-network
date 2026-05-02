/*
FILE PATH: api/openapi/spec_test.go

DESCRIPTION:
    OpenAPI 3.1 spec validation harness. The canonical artifact is
    openapi.yaml; the registered-routes table lives in
    routes_test.go. Tests here pin:

      1. The spec parses as OpenAPI 3.1 + Validate passes.
      2. Every operation has at least one response + an operationId.
      3. mTLS + bearerAuth security schemes are declared.
      4. The set of documented paths matches the set of routes the
         composer's BuildHandler actually registers — drift is a CI
         failure here.
      5. Handler() serves the spec as application/yaml.
*/
package openapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func loadSpec(t *testing.T) *openapi3.T {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(specYAML)
	if err != nil {
		t.Fatalf("LoadFromData: %v", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return doc
}

func TestSpec_ParsesAndValidates(t *testing.T) {
	doc := loadSpec(t)
	if !strings.HasPrefix(doc.OpenAPI, "3.1") {
		t.Errorf("openapi = %q, want 3.1.x", doc.OpenAPI)
	}
}

func TestSpec_HasInfo(t *testing.T) {
	doc := loadSpec(t)
	if doc.Info == nil || doc.Info.Title == "" || doc.Info.Version == "" {
		t.Error("info.title / info.version must be present")
	}
}

func TestSpec_HasSecuritySchemes(t *testing.T) {
	doc := loadSpec(t)
	if doc.Components == nil || doc.Components.SecuritySchemes == nil {
		t.Fatal("missing components.securitySchemes")
	}
	for _, want := range []string{"mTLS", "bearerAuth"} {
		if _, ok := doc.Components.SecuritySchemes[want]; !ok {
			t.Errorf("missing security scheme %q", want)
		}
	}
}

func TestSpec_EveryOperationHasResponsesAndID(t *testing.T) {
	doc := loadSpec(t)
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if op.Responses == nil || op.Responses.Len() == 0 {
				t.Errorf("%s %s has no responses", method, path)
			}
			if op.OperationID == "" {
				t.Errorf("%s %s missing operationId", method, path)
			}
		}
	}
}

func TestSpec_DocumentedPathsMatchRegisteredRoutes(t *testing.T) {
	doc := loadSpec(t)

	for _, r := range registeredRoutes {
		item := doc.Paths.Find(r.path)
		if item == nil {
			t.Errorf("registered route %s %s not documented", r.method, r.path)
			continue
		}
		if op := operationByMethod(item, r.method); op == nil {
			t.Errorf("registered route %s %s: spec has path but no %s op",
				r.method, r.path, r.method)
		}
	}

	registered := map[string]bool{}
	for _, r := range registeredRoutes {
		registered[r.method+" "+r.path] = true
	}
	for path, item := range doc.Paths.Map() {
		for method := range item.Operations() {
			if !registered[method+" "+path] {
				t.Errorf("documented operation %s %s has no registered route", method, path)
			}
		}
	}
}

func operationByMethod(item *openapi3.PathItem, method string) *openapi3.Operation {
	switch strings.ToUpper(method) {
	case http.MethodGet:
		return item.Get
	case http.MethodPost:
		return item.Post
	case http.MethodPut:
		return item.Put
	case http.MethodPatch:
		return item.Patch
	case http.MethodDelete:
		return item.Delete
	}
	return nil
}

func TestHandler_ServesYAML(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/openapi.yaml", nil)
	Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/yaml") {
		t.Errorf("Content-Type = %q, want application/yaml*", got)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "openapi: 3.1") {
		head := body
		if len(head) > 40 {
			head = head[:40]
		}
		t.Errorf("body should start with 'openapi: 3.1'; got %q...", head)
	}
}

func TestSpec_NotEmpty(t *testing.T) {
	if len(Spec()) == 0 {
		t.Error("Spec() returned empty bytes")
	}
}
