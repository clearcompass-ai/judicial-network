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

// serverTrustClient is the open-HTTPS host-probe client: it pins the run CA (so
// the ledger's SERVER cert verifies) and presents NO client cert. It backs
// ledgerHTTP — a certless caller reading the ledger IS the open-HTTPS proof.
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

// NOTE: the former AssertEdgeRejectsNoClientCert (which proved the ledger edge
// REFUSED a no-client-cert caller) was retired with the zero-trust pivot: the
// ledger now serves OPEN HTTPS and ACCEPTS no-client-cert reads by design, with
// writes gated by in-body crypto. serverTrustClient (above) is the live
// realisation of that posture — it backs the host probes (ledgerHTTP).
