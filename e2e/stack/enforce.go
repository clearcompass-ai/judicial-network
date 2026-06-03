package stack

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// serverTrustClient trusts the run CA (so the SERVER cert still verifies) but
// presents NO client cert — the negative leg of the mTLS-enforcement assert.
func serverTrustClient(certsDir string) (*http.Client, error) {
	caPEM, err := os.ReadFile(filepath.Join(certsDir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("serverTrustClient: no CA certs parsed from %s", certsDir)
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: "localhost",
			// No Certificates → no client cert presented.
		}},
	}, nil
}

// AssertEdgeRejectsNoClientCert proves an mTLS edge fails CLOSED. It issues the
// SAME GET two ways and passes only if the edge answers WITH the run client cert
// and refuses WITHOUT it:
//
//   - positive leg (the run mTLS client) must reach the edge — proves the service
//     is up + healthy, so a refusal below can't be a false "it's just down";
//   - negative leg (a CA-trusting client with NO client cert) must be refused —
//     the server cert still verifies (CA-trusting), so the refusal isn't a
//     server-cert problem either; the client cert is the ONLY variable, hence the
//     refusal IS the mTLS enforcement.
//
// A refusal is either a TLS-layer rejection (RequireAndVerifyClientCert → the GET
// errors) or an app-layer rejection (4xx/5xx). Only a 2xx WITHOUT a client cert
// means the edge is NOT fail-closed. Returns nil iff enforcement holds.
func AssertEdgeRejectsNoClientCert(certsDir, url string) error {
	if ledgerBody(certsDir, url) == "" {
		return fmt.Errorf("%s unreachable WITH a client cert — cannot assert enforcement (service down?)", url)
	}
	c, err := serverTrustClient(certsDir)
	if err != nil {
		return err
	}
	resp, err := c.Get(url)
	if err != nil {
		return nil // TLS-layer rejection — fail-closed ✓
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil // app-layer rejection (4xx/5xx) — fail-closed ✓
	}
	return fmt.Errorf("%s ACCEPTED a no-client-cert request (HTTP %d) — NOT fail-closed", url, resp.StatusCode)
}
