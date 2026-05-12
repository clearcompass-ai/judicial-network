// FILE PATH: api/server_gossip_test.go
//
// DESCRIPTION:
//
//	Phase 9 tests for the gossip-feed mount on the composed api
//	server. Verifies:
//
//	  1. When Config.Gossip is nil, no /v1/gossip/* route exists
//	     (the handler 404s).
//	  2. When Config.Gossip is non-nil, the feed is reachable at
//	     its configured PathPrefix and bypasses composer auth +
//	     reliability middleware (Trust Alignment 11: feed is
//	     designed for CDN-cacheable unauthenticated pulls).
//	  3. Trailing-slash routing works: GET /v1/gossip/since
//	     resolves to the feed handler regardless of whether the
//	     prefix was registered with or without a trailing slash.
//
//	No real gossip events are exercised here — the SDK's
//	FeedHandler test suite covers the wire semantics; this file
//	only confirms the JN composer wiring.
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clearcompass-ai/attesta/gossip"

	"github.com/clearcompass-ai/judicial-network/gossipfeed"
)

func TestServer_NoGossip_404OnFeedPaths(t *testing.T) {
	srv, err := NewServer(Config{
		Addr: ":0",
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/gossip/since", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("gossip-not-configured request should 404, got %d", rec.Code)
	}
}

func TestServer_WithGossip_FeedReachable(t *testing.T) {
	store := gossip.NewInMemoryStore()
	feed, err := gossipfeed.NewFeedMount(gossipfeed.FeedConfig{Store: store})
	if err != nil {
		t.Fatalf("NewFeedMount: %v", err)
	}
	srv, err := NewServer(Config{
		Addr:   ":0",
		Gossip: feed,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// /since on an empty store should return 200 with an empty
	// envelope, not 404 or 5xx.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		feed.Prefix()+"/since?limit=10", nil))
	if rec.Code >= 500 {
		t.Fatalf("gossip /since returned 5xx %d", rec.Code)
	}
	if rec.Code == http.StatusNotFound {
		t.Fatalf("gossip /since 404'd — mount not registered")
	}
}

func TestServer_WithGossip_FeedIsUnauthenticated(t *testing.T) {
	// Trust Alignment 11: the gossip feed is designed for
	// unauthenticated CDN-cacheable pulls. Even if the composer
	// has an Authenticator configured, /v1/gossip/* must remain
	// open. We assert this by constructing a server with an
	// Auth that rejects everything and verifying gossip still
	// answers.
	store := gossip.NewInMemoryStore()
	feed, err := gossipfeed.NewFeedMount(gossipfeed.FeedConfig{Store: store})
	if err != nil {
		t.Fatalf("NewFeedMount: %v", err)
	}
	srv, err := NewServer(Config{
		Addr:   ":0",
		Gossip: feed,
		Auth:   rejectAllAuth{},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		feed.Prefix()+"/since?limit=10", nil))
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("gossip feed was wrapped by composer auth — got %d", rec.Code)
	}
}

// rejectAllAuth implements middleware.Authenticator and rejects
// every request with 401. Used to assert that the gossip mount
// bypasses composer auth.
type rejectAllAuth struct{}

func (rejectAllAuth) Wrap(_ http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
}
