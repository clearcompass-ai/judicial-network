package verification

import (
	"net/http"
	"testing"
)

func TestHTTPTileMirrors_FetcherFor(t *testing.T) {
	m, err := NewHTTPTileMirrors(map[string]string{
		"did:web:a": "https://a.example/tiles/",
		"did:web:b": "https://b.example/tiles/",
	}, http.DefaultClient)
	if err != nil {
		t.Fatalf("NewHTTPTileMirrors: %v", err)
	}
	if _, ok := m.FetcherFor("did:web:a"); !ok {
		t.Error("expected fetcher for did:web:a")
	}
	if _, ok := m.FetcherFor("did:web:b"); !ok {
		t.Error("expected fetcher for did:web:b")
	}
	if _, ok := m.FetcherFor("did:web:none"); ok {
		t.Error("unknown DID should resolve to no fetcher")
	}
}

func TestNewHTTPTileMirrors_RejectsEmptyFields(t *testing.T) {
	if _, err := NewHTTPTileMirrors(map[string]string{"": "https://x.example/"}, nil); err == nil {
		t.Error("empty log DID must error")
	}
	if _, err := NewHTTPTileMirrors(map[string]string{"did:web:a": ""}, nil); err == nil {
		t.Error("empty URL must error")
	}
}

func TestNewHTTPTileMirrors_EmptyResolvesNothing(t *testing.T) {
	m, err := NewHTTPTileMirrors(nil, nil)
	if err != nil {
		t.Fatalf("NewHTTPTileMirrors(nil): %v", err)
	}
	if _, ok := m.FetcherFor("did:any"); ok {
		t.Error("empty resolver must resolve nothing")
	}
}
