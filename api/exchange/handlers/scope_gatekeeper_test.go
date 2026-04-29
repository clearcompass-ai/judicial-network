/*
FILE PATH: api/exchange/handlers/scope_gatekeeper_test.go

COVERAGE:
    Wave 1 admission gatekeeper. Validates that BOTH the staged build
    path (EntryBuildHandler) and the build-sign-submit shortcut
    (EntryFullHandler) consult the ScopeChecker BEFORE invoking
    KeyStore.Sign. Includes coverage for InMemoryScopeChecker's
    case-insensitive matching, unknown-signer denial, empty-scope
    denial, infra-error fallback, and the AllowAll default.
*/
package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── ScopeChecker happy path: explicit AllowAll preserves prior behavior ─

func TestEntryBuildHandler_AllowAllChecker_NoChange(t *testing.T) {
	deps := testDeps(t)
	deps.ScopeChecker = AllowAllScopeChecker()
	h := NewEntryBuildHandler(deps)

	body, _ := json.Marshal(BuildRequest{
		Builder:       "root_entity",
		Destination:   "did:web:exchange.test",
		SignerDID:     "did:web:any",
		DomainPayload: json.RawMessage(`{}`),
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/entries/build", bytes.NewReader(body))
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
}

// ─── ScopeChecker denies → 403 Forbidden ──────────────────────────

func TestEntryBuildHandler_ScopeForbidden_403(t *testing.T) {
	deps := testDeps(t)
	deps.ScopeChecker = NewInMemoryScopeChecker(map[string][]string{
		"did:web:exchange:scheduler": {"daily_assignment"}, // scope doesn't include enforcement
	})
	h := NewEntryBuildHandler(deps)

	body, _ := json.Marshal(BuildRequest{
		Builder:       "enforcement",
		Destination:   "did:web:exchange.test",
		SignerDID:     "did:web:exchange:scheduler",
		DomainPayload: json.RawMessage(`{"order":"seal"}`),
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/entries/build", bytes.NewReader(body))
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	body2, _ := io_ReadAll(w)
	if !strings.Contains(string(body2), "scope_limit") {
		t.Errorf("body should mention scope_limit: %s", body2)
	}
}

// ─── EntryFullHandler also denies (gatekeeper applies pre-sign) ──

func TestEntryFullHandler_ScopeForbidden_403_BeforeSign(t *testing.T) {
	deps := testDeps(t)
	deps.ScopeChecker = NewInMemoryScopeChecker(map[string][]string{
		"did:web:exchange:scheduler": {"daily_assignment"},
	})
	h := NewEntryFullHandler(deps)

	body, _ := json.Marshal(BuildRequest{
		Builder:       "enforcement",
		Destination:   "did:web:exchange.test",
		SignerDID:     "did:web:exchange:scheduler",
		DomainPayload: json.RawMessage(`{"order":"seal"}`),
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/entries/build-sign-submit", bytes.NewReader(body))
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

// ─── ScopeChecker infra error → 500 ──────────────────────────────

type erroringChecker struct{ msg string }

func (e erroringChecker) Allowed(string, string) error {
	return errors.New(e.msg) // not ErrScopeForbidden — infra failure
}

func TestEntryBuildHandler_ScopeInfraError_500(t *testing.T) {
	deps := testDeps(t)
	deps.ScopeChecker = erroringChecker{msg: "registry down"}
	h := NewEntryBuildHandler(deps)

	body, _ := json.Marshal(BuildRequest{
		Builder:       "root_entity",
		Destination:   "did:web:exchange.test",
		SignerDID:     "did:web:any",
		DomainPayload: json.RawMessage(`{}`),
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/entries/build", bytes.NewReader(body))
	h.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

// ─── nil ScopeChecker on Dependencies = AllowAll behavior ────────

func TestEntryBuildHandler_NilChecker_DefaultsToAllowAll(t *testing.T) {
	deps := testDeps(t) // ScopeChecker zero (nil)
	h := NewEntryBuildHandler(deps)

	body, _ := json.Marshal(BuildRequest{
		Builder:       "root_entity",
		Destination:   "did:web:exchange.test",
		SignerDID:     "did:web:any",
		DomainPayload: json.RawMessage(`{}`),
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/entries/build", bytes.NewReader(body))
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (nil checker = AllowAll)", w.Code)
	}
}

// ─── InMemoryScopeChecker semantics ─────────────────────────────

func TestInMemoryScopeChecker_PermitsExactMatch(t *testing.T) {
	c := NewInMemoryScopeChecker(map[string][]string{
		"did:web:judge": {"amendment", "commentary"},
	})
	if err := c.Allowed("did:web:judge", "amendment"); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestInMemoryScopeChecker_CaseInsensitive(t *testing.T) {
	c := NewInMemoryScopeChecker(map[string][]string{
		"did:web:judge": {" Amendment "}, // padding + caps
	})
	if err := c.Allowed("did:web:judge", "AMENDMENT"); err != nil {
		t.Errorf("case-insensitive match should pass: %v", err)
	}
}

func TestInMemoryScopeChecker_UnknownSigner_Forbidden(t *testing.T) {
	c := NewInMemoryScopeChecker(map[string][]string{
		"did:web:judge": {"amendment"},
	})
	err := c.Allowed("did:web:stranger", "amendment")
	if !errors.Is(err, ErrScopeForbidden) {
		t.Errorf("err = %v, want ErrScopeForbidden", err)
	}
	if !strings.Contains(err.Error(), "stranger") {
		t.Errorf("error must mention signer DID: %v", err)
	}
}

func TestInMemoryScopeChecker_EmptyScope_Forbidden(t *testing.T) {
	c := NewInMemoryScopeChecker(map[string][]string{
		"did:web:judge": {}, // explicitly no permissions
	})
	err := c.Allowed("did:web:judge", "amendment")
	if !errors.Is(err, ErrScopeForbidden) {
		t.Errorf("err = %v, want ErrScopeForbidden (empty scope)", err)
	}
}

func TestInMemoryScopeChecker_BuilderNotInScope_Forbidden(t *testing.T) {
	c := NewInMemoryScopeChecker(map[string][]string{
		"did:web:judge": {"amendment"},
	})
	err := c.Allowed("did:web:judge", "enforcement")
	if !errors.Is(err, ErrScopeForbidden) {
		t.Errorf("err = %v, want ErrScopeForbidden", err)
	}
}

func TestInMemoryScopeChecker_NilReceiver_Errors(t *testing.T) {
	var c *InMemoryScopeChecker
	if err := c.Allowed("x", "y"); err == nil {
		t.Error("nil receiver must surface error, not nil")
	}
}

// Empty/whitespace builder names are skipped at construction so the
// roster never includes a "" key. Confirm by constructing with two
// equivalent rosters and asserting they accept the same builder.
func TestInMemoryScopeChecker_BlankEntries_Skipped(t *testing.T) {
	c := NewInMemoryScopeChecker(map[string][]string{
		"did:web:judge": {"", "  ", "amendment", "\t"},
	})
	if err := c.Allowed("did:web:judge", "amendment"); err != nil {
		t.Errorf("amendment must permit: %v", err)
	}
	// Whitespace-only entries should not match an empty/blank
	// builder request — those cleanly fail.
	if err := c.Allowed("did:web:judge", ""); err == nil {
		t.Error("empty builder name must NOT match")
	}
}

// ─── ScopeChecker is consulted BEFORE KeyStore.Sign on full path ──

type recordingKS struct {
	*mockKS
	signed bool
}

func (r *recordingKS) Sign(did string, data []byte) ([]byte, error) {
	r.signed = true
	return r.mockKS.Sign(did, data)
}

func TestEntryFullHandler_ScopeForbidden_DoesNotSign(t *testing.T) {
	deps := testDeps(t)
	rec := &recordingKS{mockKS: newMockKS()}
	deps.KeyStore = rec
	deps.ScopeChecker = NewInMemoryScopeChecker(map[string][]string{
		"did:web:test:judge": {"amendment"}, // does not allow enforcement
	})
	h := NewEntryFullHandler(deps)

	body, _ := json.Marshal(BuildRequest{
		Builder:       "enforcement",
		Destination:   "did:web:exchange.test",
		SignerDID:     "did:web:test:judge",
		DomainPayload: json.RawMessage(`{}`),
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/entries/build-sign-submit", bytes.NewReader(body))
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if rec.signed {
		t.Error("KeyStore.Sign must NOT be invoked when scope is forbidden")
	}
}

// io_ReadAll reads w.Body — separate name to avoid shadowing io.ReadAll.
func io_ReadAll(w *httptest.ResponseRecorder) ([]byte, error) {
	return w.Body.Bytes(), nil
}
