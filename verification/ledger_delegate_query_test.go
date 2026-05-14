package verification

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLedgerDelegateQuerier_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query/delegate_did/did:example:judge-007" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"entries": [
				{"sequence_number": 42, "log_time": "2026-05-10T12:00:00Z", "signer_did": "did:example:root"},
				{"sequence_number": 17, "log_time": "2026-04-01T08:00:00Z", "signer_did": "did:example:older-root"}
			],
			"count": 2
		}`))
	}))
	defer srv.Close()

	q, err := NewLedgerDelegateQuerier(LedgerDelegateQuerierConfig{
		BaseURL: srv.URL,
		LogDID:  "did:example:cases-log",
	})
	if err != nil {
		t.Fatalf("NewLedgerDelegateQuerier: %v", err)
	}
	entries, err := q.QueryByDelegateDID(context.Background(), "did:example:judge-007")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Position.Sequence != 42 || entries[0].Position.LogDID != "did:example:cases-log" {
		t.Errorf("entry[0] position = %+v", entries[0].Position)
	}
	wantTime := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	if !entries[0].LogTime.Equal(wantTime) {
		t.Errorf("entry[0] LogTime = %v, want %v", entries[0].LogTime, wantTime)
	}
	if entries[0].CanonicalBytes != nil {
		t.Errorf("entry[0] CanonicalBytes should be nil (egress mandate)")
	}
}

func TestLedgerDelegateQuerier_EmptyDID(t *testing.T) {
	q, err := NewLedgerDelegateQuerier(LedgerDelegateQuerierConfig{
		BaseURL: "http://localhost:0",
		LogDID:  "did:example:x",
	})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	_, err = q.QueryByDelegateDID(context.Background(), "")
	if !errors.Is(err, ErrDelegateQuery) {
		t.Errorf("err should wrap ErrDelegateQuery, got %v", err)
	}
}

func TestLedgerDelegateQuerier_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	q, _ := NewLedgerDelegateQuerier(LedgerDelegateQuerierConfig{
		BaseURL: srv.URL,
		LogDID:  "did:example:x",
	})
	_, err := q.QueryByDelegateDID(context.Background(), "did:example:bob")
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if !errors.Is(err, ErrDelegateQuery) {
		t.Errorf("err should wrap ErrDelegateQuery, got %v", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("err missing status code: %v", err)
	}
}

func TestLedgerDelegateQuerier_NoEntries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"entries": [], "count": 0}`))
	}))
	defer srv.Close()

	q, _ := NewLedgerDelegateQuerier(LedgerDelegateQuerierConfig{
		BaseURL: srv.URL,
		LogDID:  "did:example:x",
	})
	entries, err := q.QueryByDelegateDID(context.Background(), "did:example:bob")
	if err != nil {
		t.Fatalf("expected no error for empty result, got %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0", len(entries))
	}
}

func TestLedgerDelegateQuerier_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{ this is not json`))
	}))
	defer srv.Close()

	q, _ := NewLedgerDelegateQuerier(LedgerDelegateQuerierConfig{
		BaseURL: srv.URL,
		LogDID:  "did:example:x",
	})
	_, err := q.QueryByDelegateDID(context.Background(), "did:example:bob")
	if !errors.Is(err, ErrDelegateQuery) {
		t.Errorf("err should wrap ErrDelegateQuery, got %v", err)
	}
}

func TestLedgerDelegateQuerier_CtorRequiresBaseURLAndLogDID(t *testing.T) {
	_, err := NewLedgerDelegateQuerier(LedgerDelegateQuerierConfig{LogDID: "x"})
	if !errors.Is(err, ErrDelegateQuery) {
		t.Errorf("missing BaseURL: want ErrDelegateQuery, got %v", err)
	}
	_, err = NewLedgerDelegateQuerier(LedgerDelegateQuerierConfig{BaseURL: "http://x"})
	if !errors.Is(err, ErrDelegateQuery) {
		t.Errorf("missing LogDID: want ErrDelegateQuery, got %v", err)
	}
}
