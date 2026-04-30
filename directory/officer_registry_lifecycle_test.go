/*
FILE PATH: directory/officer_registry_lifecycle_test.go

DESCRIPTION:
    Tests for status transitions (revoke / succeed), List ordering,
    concurrency safety, and the Postgres stub. Pulled out of
    officer_registry_test.go to keep both files under the source-
    file line cap. Helpers (sampleOfficer) are shared via the same
    test package.
*/
package directory

import (
	"errors"
	"sync"
	"testing"
)

// ─── MarkRevoked / MarkSucceeded ───────────────────────────────────

func TestInMemoryRegistry_MarkRevoked(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Add(sampleOfficer("did:key:zQ3shA", "P", "chief_justice"))

	if err := r.MarkRevoked("did:key:zQ3shA"); err != nil {
		t.Fatalf("MarkRevoked: %v", err)
	}
	got, _ := r.Lookup("did:key:zQ3shA")
	if got.Status != StatusRevoked {
		t.Errorf("status: got %q, want revoked", got.Status)
	}
}

func TestInMemoryRegistry_MarkSucceeded(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Add(sampleOfficer("did:key:zQ3shA", "P", "chief_justice"))

	if err := r.MarkSucceeded("did:key:zQ3shA", "did:key:zQ3shB"); err != nil {
		t.Fatalf("MarkSucceeded: %v", err)
	}
	got, _ := r.Lookup("did:key:zQ3shA")
	if got.Status != StatusSucceeded {
		t.Errorf("status: got %q, want succeeded", got.Status)
	}
	if got.SuccessorDID != "did:key:zQ3shB" {
		t.Errorf("successor: got %q", got.SuccessorDID)
	}
}

func TestInMemoryRegistry_RevokeAfterSucceed_Refused(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Add(sampleOfficer("did:key:zQ3shA", "P", "chief_justice"))
	r.MarkSucceeded("did:key:zQ3shA", "did:key:zQ3shB")

	err := r.MarkRevoked("did:key:zQ3shA")
	if !errors.Is(err, ErrIllegalTransition) {
		t.Errorf("expected ErrIllegalTransition, got: %v", err)
	}
}

func TestInMemoryRegistry_SucceedAfterRevoke_Refused(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Add(sampleOfficer("did:key:zQ3shA", "P", "chief_justice"))
	r.MarkRevoked("did:key:zQ3shA")

	err := r.MarkSucceeded("did:key:zQ3shA", "did:key:zQ3shB")
	if !errors.Is(err, ErrIllegalTransition) {
		t.Errorf("expected ErrIllegalTransition, got: %v", err)
	}
}

func TestInMemoryRegistry_MarkSucceeded_RequiresSuccessor(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Add(sampleOfficer("did:key:zQ3shA", "P", "chief_justice"))
	err := r.MarkSucceeded("did:key:zQ3shA", "")
	if !errors.Is(err, ErrInvalidOfficer) {
		t.Errorf("expected ErrInvalidOfficer, got: %v", err)
	}
}

// ─── List / ListByRole ─────────────────────────────────────────────

func TestInMemoryRegistry_List_Order(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Add(sampleOfficer("did:key:zQ3shC", "C", "judge"))
	r.Add(sampleOfficer("did:key:zQ3shA", "A", "chief_justice"))
	r.Add(sampleOfficer("did:key:zQ3shB", "B", "judge"))

	got := r.List()
	if len(got) != 3 {
		t.Fatalf("len: got %d, want 3", len(got))
	}
	want := []string{"did:key:zQ3shA", "did:key:zQ3shB", "did:key:zQ3shC"}
	for i, w := range want {
		if got[i].DID != w {
			t.Errorf("List[%d]: got %q want %q", i, got[i].DID, w)
		}
	}
}

func TestInMemoryRegistry_ListByRole(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Add(sampleOfficer("did:key:zQ3shA", "A", "chief_justice"))
	r.Add(sampleOfficer("did:key:zQ3shB", "B", "judge"))
	r.Add(sampleOfficer("did:key:zQ3shC", "C", "judge"))

	judges := r.ListByRole("judge")
	if len(judges) != 2 {
		t.Errorf("judges len: %d, want 2", len(judges))
	}
	for _, o := range judges {
		if o.Role != "judge" {
			t.Errorf("filter leaked role %q", o.Role)
		}
	}

	none := r.ListByRole("wizard")
	if len(none) != 0 {
		t.Errorf("unknown role len: %d, want 0", len(none))
	}
}

// ─── Concurrency ──────────────────────────────────────────────────

func TestInMemoryRegistry_ConcurrentReadsSafe(t *testing.T) {
	r := NewInMemoryRegistry()
	for i := 0; i < 16; i++ {
		r.Add(sampleOfficer(
			"did:key:zQ3sh"+string(rune('A'+i)),
			"alias-"+string(rune('A'+i)),
			"judge"))
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = r.Lookup("did:key:zQ3shA")
				_ = r.List()
				_ = r.ListByRole("judge")
			}
		}()
	}
	wg.Wait()
}

// ─── Postgres stub ─────────────────────────────────────────────────

func TestPostgresOfficerRegistry_StubSurface(t *testing.T) {
	p := NewPostgresOfficerRegistry("postgres://localhost/x")
	if p.DSN() != "postgres://localhost/x" {
		t.Errorf("DSN drift: %q", p.DSN())
	}

	if _, err := p.Lookup("x"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Lookup: expected ErrNotImplemented, got: %v", err)
	}
	if _, err := p.LookupByAlias("x"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("LookupByAlias: %v", err)
	}
	if err := p.Add(sampleOfficer("did:key:zQ3shA", "x", "judge")); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Add: %v", err)
	}
	if err := p.Update(sampleOfficer("did:key:zQ3shA", "x", "judge")); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Update: %v", err)
	}
	if err := p.MarkRevoked("did"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("MarkRevoked: %v", err)
	}
	if err := p.MarkSucceeded("did", "did2"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("MarkSucceeded: %v", err)
	}
	if got := p.List(); got != nil {
		t.Errorf("List: expected nil, got %v", got)
	}
	if got := p.ListByRole("judge"); got != nil {
		t.Errorf("ListByRole: expected nil, got %v", got)
	}
}
