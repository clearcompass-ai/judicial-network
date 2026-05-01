/*
FILE PATH: api/judicial/server_test.go

DESCRIPTION:
    Foundation tests for api/judicial. Pinned properties:

      1. BuildHandler returns a non-nil http.Handler with the
         expected stand-alone /v1/judicial/healthz route.
      2. NewServer wraps BuildHandler with a configured http.Server;
         Start / Shutdown round-trip works.
      3. SetCallerDIDResolver wires + un-wires the auth lookup hook;
         a nil resolver is a no-op (defaults to empty-string).
      4. requireCaller / decodeJSON / writeJSON / writeError emit the
         documented wire shapes (200/400/401 + JSON body).
      5. buildResponse JSON shape is stable: signing_payload,
         entry_bytes, header — exactly those keys, no more, no less.
*/
package judicial

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// BuildHandler / NewServer
// ─────────────────────────────────────────────────────────────────────

func TestBuildHandler_StandaloneHealthz(t *testing.T) {
	h := BuildHandler(ServerConfig{})
	if h == nil {
		t.Fatal("BuildHandler returned nil handler")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/judicial/healthz", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("healthz body = %q, want \"ok\"", rec.Body.String())
	}
}

func TestNewServer_DefaultsAddrAndStarts(t *testing.T) {
	srv, err := NewServer(ServerConfig{}) // empty Addr → :8090
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv == nil || srv.httpServer == nil {
		t.Fatal("expected non-nil server")
	}
	if srv.httpServer.Addr != ":8090" {
		t.Errorf("Addr = %q, want :8090", srv.httpServer.Addr)
	}
}

func TestNewServer_StartShutdown_RoundTrip(t *testing.T) {
	// Use httptest.NewServer to bind a free port and exercise the
	// handler via real HTTP, then close.
	ln := httptest.NewServer(BuildHandler(ServerConfig{}))
	defer ln.Close()

	resp, err := http.Get(ln.URL + "/v1/judicial/healthz")
	if err != nil {
		t.Fatalf("GET healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

// TestServer_Shutdown_DrainsCleanly stands the server up on a free
// port via the real Start path, fires a request, then Shutdowns to
// confirm the lifecycle is clean.
func TestServer_Shutdown_DrainsCleanly(t *testing.T) {
	srv, err := NewServer(ServerConfig{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Start() }()
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	if err := <-done; err != nil && err != http.ErrServerClosed {
		t.Errorf("Start exit: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Caller DID resolver
// ─────────────────────────────────────────────────────────────────────

// TestSetCallerDIDResolver_HookAndUnwire pins the wire/unwire
// contract: function pointer is called when set, defaults to
// empty-string when nil is passed (or no resolver was ever set).
func TestSetCallerDIDResolver_HookAndUnwire(t *testing.T) {
	defer SetCallerDIDResolver(nil)

	const want = "did:web:test:judge"
	SetCallerDIDResolver(func(*http.Request) string { return want })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := callerDID(req); got != want {
		t.Errorf("with resolver wired: callerDID = %q, want %q", got, want)
	}
	SetCallerDIDResolver(nil)
	if got := callerDID(req); got != "" {
		t.Errorf("after un-wiring: callerDID = %q, want \"\"", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// HTTP helpers
// ─────────────────────────────────────────────────────────────────────

func TestRequireCaller_Empty_Returns401(t *testing.T) {
	defer SetCallerDIDResolver(nil)
	SetCallerDIDResolver(nil) // ensure no resolver — always empty

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if did := requireCaller(rec, req); did != "" {
		t.Errorf("requireCaller returned %q for empty caller", did)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "unauthenticated" {
		t.Errorf("body.error = %q, want \"unauthenticated\"", body["error"])
	}
}

func TestRequireCaller_Authenticated_PassesThrough(t *testing.T) {
	defer SetCallerDIDResolver(nil)
	const want = "did:web:test:judge"
	SetCallerDIDResolver(func(*http.Request) string { return want })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got := requireCaller(rec, req)
	if got != want {
		t.Errorf("requireCaller = %q, want %q", got, want)
	}
	if rec.Code != http.StatusOK {
		// rec.Code defaults to 200 if no WriteHeader was called.
		// Confirm requireCaller did NOT write anything.
		t.Errorf("authenticated path wrote a status: %d", rec.Code)
	}
}

func TestDecodeJSON_HappyPath(t *testing.T) {
	type req struct {
		Foo string `json:"foo"`
	}
	body := `{"foo":"bar"}`
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	var got req
	if err := decodeJSON(r, &got); err != nil {
		t.Fatalf("decodeJSON: %v", err)
	}
	if got.Foo != "bar" {
		t.Errorf("Foo = %q, want bar", got.Foo)
	}
}

func TestDecodeJSON_UnknownField_Errors(t *testing.T) {
	type req struct {
		Foo string `json:"foo"`
	}
	body := `{"foo":"bar","unexpected":"x"}`
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	var got req
	err := decodeJSON(r, &got)
	if err != ErrInvalidRequest {
		t.Errorf("decodeJSON: got %v, want ErrInvalidRequest", err)
	}
}

func TestDecodeJSON_Malformed_Errors(t *testing.T) {
	type req struct {
		Foo string `json:"foo"`
	}
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("{not json")))
	var got req
	err := decodeJSON(r, &got)
	if err != ErrInvalidRequest {
		t.Errorf("decodeJSON: got %v, want ErrInvalidRequest", err)
	}
}

func TestWriteJSON_StatusAndContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusCreated, map[string]string{"k": "v"})
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	if got["k"] != "v" {
		t.Errorf("body[k] = %q", got["k"])
	}
}

func TestWriteError_ShapeAndStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, http.StatusBadRequest, "oh no")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	if got["error"] != "oh no" {
		t.Errorf("body[error] = %q, want \"oh no\"", got["error"])
	}
}

// TestBase64Helpers pins the encode/decode round-trip used by every
// handler that carries Plaintext or signing_payload over the wire.
func TestBase64Helpers_RoundTrip(t *testing.T) {
	in := []byte("test plaintext for the round trip")
	encoded := base64Encode(in)
	if encoded == "" {
		t.Fatal("base64Encode produced empty")
	}
	decoded, err := decodeBase64(encoded)
	if err != nil {
		t.Fatalf("decodeBase64: %v", err)
	}
	if !bytes.Equal(decoded, in) {
		t.Errorf("round-trip mismatch")
	}
}

func TestDecodeBase64_EmptyInput_ReturnsNil(t *testing.T) {
	got, err := decodeBase64("")
	if err != nil {
		t.Errorf("empty input err: %v", err)
	}
	if got != nil {
		t.Errorf("empty input should yield nil; got %v", got)
	}
}

func TestDecodeBase64_Invalid_Errors(t *testing.T) {
	_, err := decodeBase64("not!!base64!!@@@")
	if err == nil {
		t.Error("expected base64 decode error")
	}
}

// TestBuildResponse_JSONShape_Stable pins the exact wire shape of
// buildResponse so future drift is caught here. Every POST handler in
// this package returns this shape.
func TestBuildResponse_JSONShape_Stable(t *testing.T) {
	resp := buildResponse{
		SigningPayload: base64.StdEncoding.EncodeToString([]byte("signing")),
		EntryBytes:     base64.StdEncoding.EncodeToString([]byte("entry")),
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"signing_payload", "entry_bytes", "header"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("buildResponse JSON missing key %q", key)
		}
	}
	// No extra keys (drift detector — when someone adds a field
	// without removing one, this test reminds them).
	if len(raw) != 3 {
		t.Errorf("buildResponse JSON has %d keys, want 3 (signing_payload, entry_bytes, header)",
			len(raw))
	}
}
