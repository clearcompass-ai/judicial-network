package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// -------------------------------------------------------------------------
// 1) Context roundtrip
// -------------------------------------------------------------------------

func TestWithSignerDID_Roundtrip(t *testing.T) {
	ctx := WithSignerDID(context.Background(), "did:web:test:judge")
	got := SignerDIDFromContext(ctx)
	if got != "did:web:test:judge" {
		t.Errorf("got %q, want did:web:test:judge", got)
	}
}

func TestSignerDIDFromContext_Empty(t *testing.T) {
	got := SignerDIDFromContext(context.Background())
	if got != "" {
		t.Errorf("empty context should return empty, got %q", got)
	}
}

// -------------------------------------------------------------------------
// 2) ExtractDIDFromCert
// -------------------------------------------------------------------------

func testCertWithDIDURI(t *testing.T, did string) *x509.Certificate {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if did != "" {
		u, _ := url.Parse(did)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func TestExtractDIDFromCert_WithURI(t *testing.T) {
	cert := testCertWithDIDURI(t, "did:web:courts.nashville.gov:criminal")
	got := ExtractDIDFromCert(cert)
	if got != "did:web:courts.nashville.gov:criminal" {
		t.Errorf("got %q", got)
	}
}

func TestExtractDIDFromCert_NoURI(t *testing.T) {
	cert := testCertWithDIDURI(t, "")
	got := ExtractDIDFromCert(cert)
	if got != "" {
		t.Errorf("no URI should return empty, got %q", got)
	}
}

// -------------------------------------------------------------------------
// 3) ExtractDIDFromRequest
// -------------------------------------------------------------------------

func TestExtractDIDFromRequest_mTLS(t *testing.T) {
	cert := testCertWithDIDURI(t, "did:web:test:judge")
	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	got := ExtractDIDFromRequest(req)
	if got != "did:web:test:judge" {
		t.Errorf("got %q", got)
	}
}

func TestExtractDIDFromRequest_NoTLS(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if got := ExtractDIDFromRequest(req); got != "" {
		t.Errorf("no TLS should return empty, got %q", got)
	}
}

func TestExtractDIDFromRequest_NoCerts(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.TLS = &tls.ConnectionState{}
	if got := ExtractDIDFromRequest(req); got != "" {
		t.Errorf("no certs should return empty, got %q", got)
	}
}

// -------------------------------------------------------------------------
// 4) BuildCertSAN
// -------------------------------------------------------------------------

func TestBuildCertSAN_Valid(t *testing.T) {
	u, err := BuildCertSAN("did:web:courts.nashville.gov")
	if err != nil {
		t.Fatalf("BuildCertSAN: %v", err)
	}
	if u.String() != "did:web:courts.nashville.gov" {
		t.Errorf("SAN = %q", u.String())
	}
}

// -------------------------------------------------------------------------
// 5) NonceStore
// -------------------------------------------------------------------------

func TestNonceStore_CheckUnique(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)
	if !ns.Check("nonce-1", time.Now()) {
		t.Error("first use of nonce should pass")
	}
	if ns.Check("nonce-1", time.Now()) {
		t.Error("replay of same nonce should fail")
	}
}

func TestNonceStore_CheckDifferentNonces(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)
	if !ns.Check("a", time.Now()) {
		t.Error("nonce a should pass")
	}
	if !ns.Check("b", time.Now()) {
		t.Error("nonce b should pass")
	}
}

// -------------------------------------------------------------------------
// 6) SignerAuth.Wrap: no auth → 401
// -------------------------------------------------------------------------

func TestSignerAuth_Wrap_NoAuth_401(t *testing.T) {
	sa := NewSignerAuth("http://localhost:8080")
	handler := sa.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/v1/build", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("no auth: status = %d, want 401", w.Code)
	}
}

// -------------------------------------------------------------------------
// 7) SignerAuth.Wrap: mTLS injects context
// -------------------------------------------------------------------------

func TestSignerAuth_Wrap_mTLS_InjectsContext(t *testing.T) {
	cert := testCertWithDIDURI(t, "did:web:test:judge")

	var captured string
	sa := NewSignerAuth("http://localhost:8080")
	handler := sa.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = SignerDIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/v1/build", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if captured != "did:web:test:judge" {
		t.Errorf("captured = %q", captured)
	}
}
