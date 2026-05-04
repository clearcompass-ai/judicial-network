package courts

import (
	"context"
	"net/http"
	"strings"

	"github.com/clearcompass-ai/judicial-network/tools/common"
)

type contextKey string

const signerDIDContextKey contextKey = "signer_did"

// SignerDIDFromContext extracts the authenticated signer DID from context.
func SignerDIDFromContext(ctx context.Context) string {
	did, _ := ctx.Value(signerDIDContextKey).(string)
	return did
}

// AuthMiddleware resolves authenticated identity → signing DID.
// Supports two modes:
//
//	mTLS: DID extracted from client certificate SAN (CMS systems like Tyler Odyssey)
//	SSO:  DID resolved from Bearer token via court SSO (human operators)
//
// Downstream handlers receive the signer DID in context regardless of auth mode.
func AuthMiddleware(cfg common.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var signerDID string

			// Mode 1: mTLS — DID from client certificate SAN.
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				cert := r.TLS.PeerCertificates[0]
				for _, uri := range cert.URIs {
					if strings.HasPrefix(uri.String(), "did:") {
						signerDID = uri.String()
						break
					}
				}
				if signerDID == "" && len(cert.DNSNames) > 0 {
					// Fallback: derive DID from DNS SAN.
					signerDID = "did:web:" + cert.DNSNames[0]
				}
			}

			// Mode 2: SSO — Bearer token. In production, validate against
			// cfg.CourtSSOIssuer (OIDC discovery + token verification).
			// The token's subject maps to a role-scoped DID via officer registry.
			if signerDID == "" {
				auth := r.Header.Get("Authorization")
				if strings.HasPrefix(auth, "Bearer ") {
					token := strings.TrimPrefix(auth, "Bearer ")
					signerDID = resolveTokenToDID(cfg, token)
				}
			}

			// Mode 3: X-Signer-DID header (dev/sandbox only).
			if signerDID == "" {
				signerDID = r.Header.Get("X-Signer-DID")
			}

			if signerDID == "" {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			ctx := context.WithValue(r.Context(), signerDIDContextKey, signerDID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// resolveTokenToDID validates a Bearer token and maps it to a signer DID.
// In production: OIDC token validation + officer registry lookup.
// Stub implementation for compilation.
func resolveTokenToDID(cfg common.Config, token string) string {
	// TODO: Validate token against cfg.CourtSSOIssuer.
	// TODO: Map token subject to role-scoped DID via officer registry.
	// For sandbox: token IS the DID.
	if strings.HasPrefix(token, "did:") {
		return token
	}
	return ""
}
