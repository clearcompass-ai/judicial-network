// Package httpx is the thin HTTP plumbing shared by the typed component
// clients (../clients): JSON/raw GET+POST, optional mTLS, health probes, and
// a poller. It has no testing dependency, so the same clients drive both the
// `go test` scenarios and any future standalone validator binary.
package httpx

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	maxBody        = 8 << 20 // response read cap
	defaultTimeout = 10 * time.Second
)

// Client is a base-URL-scoped HTTP client.
type Client struct {
	Base string
	HTTP *http.Client
}

// New returns a plain client rooted at base.
func New(base string) *Client {
	return &Client{Base: trimSlash(base), HTTP: &http.Client{Timeout: defaultTimeout}}
}

// NewMTLS returns a client that presents a client cert and trusts caFile —
// for the JN enforcer (RequireAndVerifyClientCert).
func NewMTLS(base, caFile, certFile, keyFile string) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert (%s/%s): %w", certFile, keyFile, err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA %s: no certificates parsed", caFile)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
	}}
	return &Client{Base: trimSlash(base), HTTP: &http.Client{Timeout: defaultTimeout, Transport: tr}}, nil
}

// NewServerTrust returns a client that trusts caFile but presents NO client
// certificate — used to prove the JN enforcer rejects an unauthenticated
// caller at the TLS layer (S5.1, S7.8).
func NewServerTrust(base, caFile string) (*Client, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA %s: no certificates parsed", caFile)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	return &Client{Base: trimSlash(base), HTTP: &http.Client{Timeout: defaultTimeout, Transport: tr}}, nil
}

// GetRaw GETs path; returns status + body bytes.
func (c *Client) GetRaw(path string) (int, []byte, error) {
	resp, err := c.HTTP.Get(c.Base + path)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp.StatusCode, b, nil
}

// GetJSON GETs path; on a 2xx it unmarshals the body into out (if non-nil).
func (c *Client) GetJSON(path string, out any) (int, error) {
	code, b, err := c.GetRaw(path)
	if err != nil {
		return code, err
	}
	if out != nil && code/100 == 2 {
		if err := json.Unmarshal(b, out); err != nil {
			return code, fmt.Errorf("GET %s decode (status %d): %w; body=%s", path, code, err, snippet(b))
		}
	}
	return code, nil
}

// PostRaw POSTs body with contentType; returns status + response bytes.
func (c *Client) PostRaw(path, contentType string, body []byte) (int, []byte, error) {
	resp, err := c.HTTP.Post(c.Base+path, contentType, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp.StatusCode, b, nil
}

// PostJSON marshals in, POSTs it as application/json, and decodes a 2xx
// response into out (if non-nil).
func (c *Client) PostJSON(path string, in, out any) (int, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}
	code, b, err := c.PostRaw(path, "application/json", body)
	if err != nil {
		return code, err
	}
	if out != nil && code/100 == 2 {
		if err := json.Unmarshal(b, out); err != nil {
			return code, fmt.Errorf("POST %s decode (status %d): %w; body=%s", path, code, err, snippet(b))
		}
	}
	return code, nil
}

// Health GETs /healthz; returns status + trimmed body.
func (c *Client) Health() (int, string, error) { return c.textGet("/healthz") }

// Ready GETs /readyz; returns status + trimmed body.
func (c *Client) Ready() (int, string, error) { return c.textGet("/readyz") }

func (c *Client) textGet(path string) (int, string, error) {
	code, b, err := c.GetRaw(path)
	return code, string(bytes.TrimSpace(b)), err
}

// Poll calls fn until it returns (true, _) or timeout elapses; returns true
// on success. fn errors are treated as "not ready yet".
func Poll(timeout, interval time.Duration, fn func() (bool, error)) bool {
	deadline := time.Now().Add(timeout)
	for {
		if ok, _ := fn(); ok {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(interval)
	}
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func snippet(b []byte) string {
	if len(b) > 256 {
		return string(b[:256]) + "…"
	}
	return string(b)
}
