/*
FILE PATH: api/middleware/reliability/transport.go

DESCRIPTION:

	Tuned http.Transport for the JN binary's outbound HTTP. The
	primary call site is `submitToLedger` in
	api/exchange/handlers/management.go, which previously used
	`sdklog.DefaultClient(30s)` — that path inherits Go's stdlib
	defaults including `MaxIdleConnsPerHost: 2`, which silently
	caps each replica to ~2 concurrent ledger submits regardless
	of CPU.

	Production deployments expect ~1000 TPS sustained. With the
	stdlib default, JN spends most of its time waiting for free
	connections instead of submitting; tail latencies blow up,
	which the ledger perceives as load that isn't really there.

	This package exposes:

	  - NewTunedClient(...)  — *http.Client with sane production
	    defaults (MaxIdleConnsPerHost 256, MaxConnsPerHost 1024,
	    IdleConnTimeout 90s, ResponseHeaderTimeout 10s, expect-
	    continue 1s). Single source of truth — the binary swaps
	    sdklog.DefaultClient for this at boot.

	  - DefaultClientConfig — the default *Config* values surfaced
	    as named constants so ledgers can override per-deploy.

	No tunable defeats correctness. The settings here protect tail
	latency under load; they do not change semantics.
*/
package reliability

import (
	"net"
	"net/http"
	"time"
)

// ClientConfig configures NewTunedClient. Zero values fall back
// to the documented production defaults.
type ClientConfig struct {
	// Timeout is the per-request wall-clock cap (TCP dial through
	// response body fully read). Default: 30s.
	Timeout time.Duration

	// MaxIdleConnsPerHost caps idle connections retained per host.
	// At 1000 TPS sustained the stdlib default (2) is the wrong
	// number by ~3 orders of magnitude. Default: 256.
	MaxIdleConnsPerHost int

	// MaxConnsPerHost caps total connections (idle + in-flight)
	// per host. Default: 1024.
	MaxConnsPerHost int

	// IdleConnTimeout is the keep-alive duration for idle connections.
	// Default: 90s — matches the AWS ELB idle-timeout default so
	// connections aren't closed underneath us.
	IdleConnTimeout time.Duration

	// ResponseHeaderTimeout caps how long we wait for the *header*
	// of the response after the request body is fully written.
	// Detects backend hangs without aborting healthy slow operations.
	// Default: 10s.
	ResponseHeaderTimeout time.Duration

	// DialTimeout caps TCP-dial time. Default: 5s.
	DialTimeout time.Duration

	// ExpectContinueTimeout is the wait-for-100-Continue deadline.
	// Default: 1s.
	ExpectContinueTimeout time.Duration

	// TLSHandshakeTimeout caps TLS handshake. Default: 10s.
	TLSHandshakeTimeout time.Duration
}

// DefaultClientConfig returns the production-tuned defaults.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Timeout:               30 * time.Second,
		MaxIdleConnsPerHost:   256,
		MaxConnsPerHost:       1024,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DialTimeout:           5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
	}
}

// NewTunedClient returns an *http.Client wired with a Transport
// configured for high-concurrency outbound calls. Pass the zero
// ClientConfig{} to get the defaults; pass a partially-populated
// Config to override specific fields.
func NewTunedClient(cfg ClientConfig) *http.Client {
	d := DefaultClientConfig()
	if cfg.Timeout > 0 {
		d.Timeout = cfg.Timeout
	}
	if cfg.MaxIdleConnsPerHost > 0 {
		d.MaxIdleConnsPerHost = cfg.MaxIdleConnsPerHost
	}
	if cfg.MaxConnsPerHost > 0 {
		d.MaxConnsPerHost = cfg.MaxConnsPerHost
	}
	if cfg.IdleConnTimeout > 0 {
		d.IdleConnTimeout = cfg.IdleConnTimeout
	}
	if cfg.ResponseHeaderTimeout > 0 {
		d.ResponseHeaderTimeout = cfg.ResponseHeaderTimeout
	}
	if cfg.DialTimeout > 0 {
		d.DialTimeout = cfg.DialTimeout
	}
	if cfg.ExpectContinueTimeout > 0 {
		d.ExpectContinueTimeout = cfg.ExpectContinueTimeout
	}
	if cfg.TLSHandshakeTimeout > 0 {
		d.TLSHandshakeTimeout = cfg.TLSHandshakeTimeout
	}
	dialer := &net.Dialer{
		Timeout:   d.DialTimeout,
		KeepAlive: 30 * time.Second,
	}
	return &http.Client{
		Timeout: d.Timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			MaxIdleConnsPerHost:   d.MaxIdleConnsPerHost,
			MaxConnsPerHost:       d.MaxConnsPerHost,
			IdleConnTimeout:       d.IdleConnTimeout,
			ResponseHeaderTimeout: d.ResponseHeaderTimeout,
			ExpectContinueTimeout: d.ExpectContinueTimeout,
			TLSHandshakeTimeout:   d.TLSHandshakeTimeout,
			ForceAttemptHTTP2:     true,
		},
	}
}
