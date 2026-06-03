package main

import (
	"context"
	"errors"
	"testing"

	"github.com/clearcompass-ai/judicial-network/api/config"
)

type fakePeerResolver struct {
	m   map[string]string
	err error
}

func (f fakePeerResolver) LedgerEndpoint(_ context.Context, didWeb string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.m[didWeb], nil
}

func TestIsDIDWeb(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"did:web:ledger.davidson.gov", true},
		{"did:web:b", true},
		{"http://b.example", false},
		{"https://ledger.example", false},
		{"did:key:z6Mk", false},
		{"", false},
	} {
		if got := isDIDWeb(c.in); got != c.want {
			t.Errorf("isDIDWeb(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// A bare did:web base resolves to its BaseproofLedger endpoint; the LogDID
// (originator routing key) is untouched.
func TestResolveGossipPeerEndpoints_DIDWebResolved(t *testing.T) {
	res := fakePeerResolver{m: map[string]string{
		"did:web:ledger.davidson.gov": "https://ledger.davidson.gov",
	}}
	in := []config.GossipPeerConfig{
		{LogDID: "did:key:zOriginator", BaseURL: "did:web:ledger.davidson.gov"},
	}
	out, err := resolveGossipPeerEndpoints(context.Background(), in, res)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if out[0].BaseURL != "https://ledger.davidson.gov" {
		t.Errorf("BaseURL = %q, want resolved URL", out[0].BaseURL)
	}
	if out[0].LogDID != "did:key:zOriginator" {
		t.Errorf("LogDID mutated: %q", out[0].LogDID)
	}
	// Input slice must not be mutated.
	if in[0].BaseURL != "did:web:ledger.davidson.gov" {
		t.Errorf("input mutated: %q", in[0].BaseURL)
	}
}

// http(s) bases pass through verbatim — resolver is never consulted (it would
// error if it were, since the map is empty).
func TestResolveGossipPeerEndpoints_HTTPPassthrough(t *testing.T) {
	res := fakePeerResolver{err: errors.New("must not be called")}
	in := []config.GossipPeerConfig{
		{LogDID: "did:key:z1", BaseURL: "http://b.example"},
		{LogDID: "did:key:z2", BaseURL: "https://c.example"},
	}
	out, err := resolveGossipPeerEndpoints(context.Background(), in, res)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if out[0].BaseURL != "http://b.example" || out[1].BaseURL != "https://c.example" {
		t.Errorf("http(s) bases altered: %+v", out)
	}
}

// A mixed list (bare did:web + explicit URL) works.
func TestResolveGossipPeerEndpoints_Mixed(t *testing.T) {
	res := fakePeerResolver{m: map[string]string{"did:web:a": "https://a.example"}}
	in := []config.GossipPeerConfig{
		{LogDID: "did:key:zA", BaseURL: "did:web:a"},
		{LogDID: "did:key:zB", BaseURL: "https://b.example"},
	}
	out, err := resolveGossipPeerEndpoints(context.Background(), in, res)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if out[0].BaseURL != "https://a.example" || out[1].BaseURL != "https://b.example" {
		t.Errorf("mixed resolution wrong: %+v", out)
	}
}

func TestResolveGossipPeerEndpoints_NoResolverFailsClosed(t *testing.T) {
	in := []config.GossipPeerConfig{{LogDID: "did:key:z", BaseURL: "did:web:a"}}
	if _, err := resolveGossipPeerEndpoints(context.Background(), in, nil); err == nil {
		t.Fatal("nil resolver with a did:web base did not fail closed")
	}
}

func TestResolveGossipPeerEndpoints_UnresolvableFailsClosed(t *testing.T) {
	res := fakePeerResolver{err: errors.New("did:web fetch failed")}
	in := []config.GossipPeerConfig{{LogDID: "did:key:z", BaseURL: "did:web:gone"}}
	if _, err := resolveGossipPeerEndpoints(context.Background(), in, res); err == nil {
		t.Fatal("unresolvable did:web did not fail closed")
	}
}

func TestResolveGossipPeerEndpoints_EmptyEndpointFailsClosed(t *testing.T) {
	// Resolver returns "" (DID doc has no BaseproofLedger service endpoint).
	res := fakePeerResolver{m: map[string]string{"did:web:noledger": ""}}
	in := []config.GossipPeerConfig{{LogDID: "did:key:z", BaseURL: "did:web:noledger"}}
	if _, err := resolveGossipPeerEndpoints(context.Background(), in, res); err == nil {
		t.Fatal("empty resolved endpoint did not fail closed")
	}
}
