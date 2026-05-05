/*
FILE PATH: api/server_helpers.go

DESCRIPTION:

	Composer-side helpers split out of server.go so that file stays
	under the 300-line cap. Owns:

	  - wrapReliability :  RateLimitGlobal / RequestTimeout /
	    MaxBodyBytes wrapper composition.
	  - buildMTLSConfig : reads the client-CA PEM and builds the
	    *tls.Config that REQUIRES client certs verified against it.

	server.go retains Config / NewServer / Server / Handler / Start /
	StartTLS / Shutdown — the public surface — and dispatches into
	these helpers.
*/
package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/time/rate"

	"github.com/clearcompass-ai/judicial-network/api/middleware/reliability"
)

// wrapReliability stacks the  reliability middleware in
// outer-to-inner order:
//
//	RateLimitGlobal → RequestTimeout → MaxBodyBytes → next
//
// Each wrapper is opt-in. Zero values for the limit / timeout /
// rate fields fall through to "no wrapper" so dev and test
// configurations can leave them unset and run with the bare auth
// + handler stack.
//
// MaxBodyBytes is special: cfg.MaxBodyBytes == 0 applies the
// production default (1 MiB) — the most common 0-value-vs-default
// confusion across the Config struct. Ledgers that legitimately
// need oversized payloads set the field to -1 to disable.
func wrapReliability(cfg Config, next http.Handler) http.Handler {
	body := cfg.MaxBodyBytes
	if body == 0 {
		body = reliability.DefaultMaxBodyBytes
	}
	if body > 0 {
		next = reliability.MaxBodyBytes(body, next)
	}
	if cfg.PerRequestTimeout != 0 {
		t := cfg.PerRequestTimeout
		if t < 0 {
			t = 0
		}
		next = reliability.RequestTimeout(t, next)
	}
	if cfg.GlobalRPS > 0 && cfg.GlobalBurst > 0 {
		next = reliability.RateLimitGlobal(rate.Limit(cfg.GlobalRPS), cfg.GlobalBurst, next)
	}
	return next
}

// buildMTLSConfig reads the client-CA PEM file and returns a
// *tls.Config that REQUIRES client certs verified against that CA.
// The previous mTLS contract: every authenticated request presents
// a client cert whose SAN contains the signer's DID; auth middleware
// extracts callerDID from the verified cert and threads it
// into request context.
func buildMTLSConfig(caFile string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("%w: read ClientCAFile %q: %w", ErrInvalidConfig, caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: ClientCAFile %q has no PEM certs", ErrInvalidConfig, caFile)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
	}, nil
}
