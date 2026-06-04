/*
FILE PATH:

	api/exchange/auth/v2/verify.go

DESCRIPTION:

	VerifyRequest checks a v2 Request end-to-end against the SDK's
	exchange-auth gate. Replay protection, validity window,
	clock-skew tolerance, domain match, and field hygiene all run
	against the envelope unchanged (the SDK's contract); the
	signature is verified against Request.SigningBytes() via the
	SDK's CanonicalBytes seam.

	The function is a thin orchestrator — its load-bearing call is
	sdkauth.VerifyRequest with a CanonicalBytes callback. Everything
	else is "make sure the SDK's gates are armed correctly."
*/
package v2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/did"
	sdkauth "github.com/baseproof/baseproof/exchange/auth"
)

// VerifyOptions configures VerifyRequest. The shape mirrors
// sdkauth.VerifyRequestOptions for the SDK-side knobs, then adds
// JN-specific knobs (ExpectedAction).
type VerifyOptions struct {
	// ExpectedDomain, if set, requires the envelope's Domain to
	// match exactly. The SDK enforces this; we pass it through.
	ExpectedDomain string

	// ExpectedAction, if set, requires Request.Action to equal it.
	// Surfaces "wrong action for this endpoint" as a typed error
	// rather than the SDK's generic signature-mismatch. JN
	// handlers pin this per route.
	ExpectedAction string

	// ValidityWindow is the maximum (ExpiresAt - IssuedAt) the
	// caller accepts. Zero defaults to sdkauth.MaxValidityWindow
	// (the SDK's 1h ceiling — values above it are rejected).
	ValidityWindow time.Duration

	// ClockSkew tolerance. Zero defaults to sdkauth.MaxClockSkew.
	ClockSkew time.Duration

	// Now is exposed for tests. nil means time.Now.
	Now func() time.Time
}

// VerifyRequest runs the SDK envelope gate + the JN extension
// checks against req.
//
// The verification order is the SDK's order (field hygiene -> clock
// skew -> validity window -> domain match -> nonce reserve ->
// signature) plus a JN check at the end of the SDK chain:
// ExpectedAction equality. Returns wrapped sdkauth errors on SDK-
// surface failures and ErrActionMismatch on the JN extension.
func VerifyRequest(
	ctx context.Context,
	registry *did.VerifierRegistry,
	req *Request,
	algoID uint16,
	nonces sdkauth.NonceStore,
	opts VerifyOptions,
) error {
	if req == nil {
		return fmt.Errorf("auth/v2: nil Request")
	}
	if opts.ExpectedAction != "" && req.Action != opts.ExpectedAction {
		// Surface BEFORE invoking the SDK so a misrouted request
		// doesn't burn a nonce or charge crypto work.
		return fmt.Errorf("%w: got %q, want %q",
			ErrActionMismatch, req.Action, opts.ExpectedAction)
	}
	return sdkauth.VerifyRequest(
		ctx, registry, &req.Envelope, req.Signature, algoID, nonces,
		sdkauth.VerifyRequestOptions{
			ExpectedDomain: opts.ExpectedDomain,
			ValidityWindow: opts.ValidityWindow,
			ClockSkew:      opts.ClockSkew,
			Now:            opts.Now,
			// THE LOAD-BEARING SEAM. CanonicalBytes is the only
			// way to bind a domain-extension into the SDK's
			// signature verification while keeping every other
			// SDK gate (nonce, domain, validity, hygiene) running
			// against the envelope. See baseproof v1.34 CHANGELOG.
			CanonicalBytes: req.SigningBytes,
		},
	)
}

// ErrActionMismatch is returned by VerifyRequest when opts.ExpectedAction
// is set and req.Action differs.
var ErrActionMismatch = errors.New("auth/v2: action does not match endpoint")
