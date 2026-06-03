package stack

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeMTLSCerts mints a CA + a server cert (SAN localhost/127.0.0.1) + a client
// cert, all chaining to the CA, into dir under the .run/{id}/certs layout the
// helpers expect (ca.crt, server.crt, server.key, client.crt, client.key).
// In-process (crypto/x509) so the test is hermetic — no openssl dependency.
func writeMTLSCerts(t *testing.T, dir string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "baseproof-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	writePEM(t, dir, "ca.crt", "CERTIFICATE", caDER)

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	writePEM(t, dir, "server.crt", "CERTIFICATE", srvDER)
	writeECKey(t, dir, "server.key", srvKey)

	cliKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "baseproof-test-client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, _ := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, &cliKey.PublicKey, caKey)
	writePEM(t, dir, "client.crt", "CERTIFICATE", cliDER)
	writeECKey(t, dir, "client.key", cliKey)
}

func writePEM(t *testing.T, dir, name, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeECKey(t *testing.T, dir, name string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, dir, name, "EC PRIVATE KEY", der)
}

// mtlsTestServer stands up an httptest TLS server using dir's server cert, with
// the given client-auth policy (RequireAndVerifyClientCert = the enforcing edge;
// NoClientCert = a non-enforcing edge). /healthz returns "ok".
func mtlsTestServer(t *testing.T, dir string, clientAuth tls.ClientAuthType) *httptest.Server {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: clientAuth}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// An enforcing edge (RequireAndVerifyClientCert) must pass the assert: reachable
// with the client cert, refused without it.
func TestAssertEdgeRejectsNoClientCert_EnforcingPasses(t *testing.T) {
	dir := t.TempDir()
	writeMTLSCerts(t, dir)
	srv := mtlsTestServer(t, dir, tls.RequireAndVerifyClientCert)
	if err := AssertEdgeRejectsNoClientCert(dir, srv.URL+"/healthz"); err != nil {
		t.Errorf("enforcing edge should pass the assert, got: %v", err)
	}
}

// A non-enforcing edge (NoClientCert accepts a certless caller) must be DETECTED:
// the assert returns an error because the no-client-cert leg succeeded.
func TestAssertEdgeRejectsNoClientCert_DetectsUnenforced(t *testing.T) {
	dir := t.TempDir()
	writeMTLSCerts(t, dir)
	srv := mtlsTestServer(t, dir, tls.NoClientCert)
	if err := AssertEdgeRejectsNoClientCert(dir, srv.URL+"/healthz"); err == nil {
		t.Error("non-enforcing edge accepted a no-client-cert request — assert must FAIL, but it passed")
	}
}

// A down edge must not produce a false pass: the positive leg fails first.
func TestAssertEdgeRejectsNoClientCert_DownEdgeNoFalsePass(t *testing.T) {
	dir := t.TempDir()
	writeMTLSCerts(t, dir)
	if err := AssertEdgeRejectsNoClientCert(dir, "https://127.0.0.1:1/healthz"); err == nil {
		t.Error("a down edge must fail the assert (positive leg), not falsely pass")
	}
}
