/*
FILE PATH: api/exchange/auth/v2/mtls.go

DESCRIPTION:

	Extracts DID from a client certificate's SAN (Subject Alternative
	Name) URI field. Standard X.509 extension — the DID is encoded as:

	  SAN: URI:did:web:courts.nashville.gov:role:judge-mcclendon-2026

	This replaces bearer tokens. The TLS handshake proves the caller
	controls the private key for the cert. The SAN DID links the cert
	to the on-log delegation chain.

	No sessions table. No token issuance. No token refresh.
	The cert IS the credential. Revocation is on-log (BuildRevocation
	against the DID's delegation), not CRL-based.

	SANCertExtractor implements the v2 MTLSExtractor interface — wire
	an instance into SignerAuthConfig.MTLSExtractor to enable the mTLS
	auth path on an exchange listener.
*/
package v2

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// SANCertExtractor is the v2 MTLSExtractor implementation that
// reads a DID from the first URI SAN starting with "did:" on the
// client cert. The zero value is the production-ready instance.
type SANCertExtractor struct{}

// ExtractDIDFromRequest implements MTLSExtractor.
func (SANCertExtractor) ExtractDIDFromRequest(r *http.Request) string {
	return ExtractDIDFromRequest(r)
}

// Compile-time confirmation that SANCertExtractor satisfies the
// MTLSExtractor interface.
var _ MTLSExtractor = SANCertExtractor{}

// ExtractDIDFromCert reads the DID from the first URI SAN that
// starts with "did:". Returns empty string if no DID SAN is
// present (caller may be using signed request auth instead).
func ExtractDIDFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, uri := range cert.URIs {
		if strings.HasPrefix(uri.String(), "did:") {
			return uri.String()
		}
	}
	return ""
}

// ExtractDIDFromRequest extracts the caller's DID from the TLS
// client certificate. Returns empty string if no client cert or
// no DID SAN.
func ExtractDIDFromRequest(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return ExtractDIDFromCert(r.TLS.PeerCertificates[0])
}

// BuildCertSAN creates a URI for embedding a DID in a certificate
// SAN. Used by cert generation tooling.
func BuildCertSAN(did string) (*url.URL, error) {
	if !strings.HasPrefix(did, "did:") {
		return nil, fmt.Errorf("auth/v2/mtls: invalid DID: %s", did)
	}
	return url.Parse(did)
}
