/*
FILE PATH: directory/attorney_registry_lifecycle_test.go

DESCRIPTION:
    Lifecycle, listing, and concurrency tests for InMemoryAttorneys.
    Helpers (sampleAttorney) are shared from attorney_registry_test.go
    in the same test package.

    Pins the legal status invariants:
      - Active → Suspended (with reason) → Active (Restore).
      - Active / Suspended → Retired (terminal).
      - Active / Suspended → Revoked (terminal).
      - Retired ↔ Revoked: cannot cross between terminals.
      - Update with Status=Active is refused once terminal.
*/
package directory

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// ─── Suspend / Restore ──────────────────────────────────────────────

func TestInMemoryAttorneys_Suspend_Restore(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Jane", "TN-1", AttorneyTypeProsecutor))

	if err := r.Suspend("bar:1", "ethics_inquiry"); err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	got, _ := r.Lookup("bar:1")
	if got.Status != AttorneySuspended {
		t.Errorf("status: got %q, want suspended", got.Status)
	}
	if got.SuspensionReason != "ethics_inquiry" {
		t.Errorf("reason drift: %q", got.SuspensionReason)
	}

	if err := r.Restore("bar:1"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got, _ = r.Lookup("bar:1")
	if got.Status != AttorneyActive {
		t.Errorf("post-restore status: %q", got.Status)
	}
	if got.SuspensionReason != "" {
		t.Errorf("suspension reason not cleared: %q", got.SuspensionReason)
	}
}

func TestInMemoryAttorneys_Suspend_RequiresReason(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Jane", "TN-1", AttorneyTypeProsecutor))
	err := r.Suspend("bar:1", "")
	if !errors.Is(err, ErrInvalidAttorney) {
		t.Errorf("expected ErrInvalidAttorney, got: %v", err)
	}
}

func TestInMemoryAttorneys_Suspend_NotFound(t *testing.T) {
	r := NewInMemoryAttorneys()
	err := r.Suspend("bar:GHOST", "reason")
	if !errors.Is(err, ErrAttorneyNotFound) {
		t.Errorf("expected ErrAttorneyNotFound, got: %v", err)
	}
}

func TestInMemoryAttorneys_Restore_RefusedWhenNotSuspended(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Jane", "TN-1", AttorneyTypeProsecutor))

	// Active → Restore is illegal (no-op transition).
	err := r.Restore("bar:1")
	if !errors.Is(err, ErrIllegalAttorneyTransition) {
		t.Errorf("expected ErrIllegalAttorneyTransition (active), got: %v", err)
	}

	// Retired → Restore is illegal (terminal).
	r.Retire("bar:1")
	err = r.Restore("bar:1")
	if !errors.Is(err, ErrIllegalAttorneyTransition) {
		t.Errorf("expected ErrIllegalAttorneyTransition (retired), got: %v", err)
	}
}

// ─── Retire / Revoke (terminals) ────────────────────────────────────

func TestInMemoryAttorneys_Retire(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Jane", "TN-1", AttorneyTypeProsecutor))

	if err := r.Retire("bar:1"); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	got, _ := r.Lookup("bar:1")
	if got.Status != AttorneyRetired {
		t.Errorf("status: got %q, want retired", got.Status)
	}
}

func TestInMemoryAttorneys_Revoke(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Jane", "TN-1", AttorneyTypeProsecutor))

	if err := r.Revoke("bar:1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, _ := r.Lookup("bar:1")
	if got.Status != AttorneyRevoked {
		t.Errorf("status: got %q, want revoked", got.Status)
	}
}

func TestInMemoryAttorneys_Retire_AfterRevokeRefused(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Jane", "TN-1", AttorneyTypeProsecutor))
	r.Revoke("bar:1")
	err := r.Retire("bar:1")
	if !errors.Is(err, ErrIllegalAttorneyTransition) {
		t.Errorf("expected ErrIllegalAttorneyTransition, got: %v", err)
	}
}

func TestInMemoryAttorneys_Revoke_AfterRetireRefused(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Jane", "TN-1", AttorneyTypeProsecutor))
	r.Retire("bar:1")
	err := r.Revoke("bar:1")
	if !errors.Is(err, ErrIllegalAttorneyTransition) {
		t.Errorf("expected ErrIllegalAttorneyTransition, got: %v", err)
	}
}

func TestInMemoryAttorneys_Suspend_AfterTerminalRefused(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Jane", "TN-1", AttorneyTypeProsecutor))
	r.Retire("bar:1")
	err := r.Suspend("bar:1", "reason")
	if !errors.Is(err, ErrIllegalAttorneyTransition) {
		t.Errorf("expected ErrIllegalAttorneyTransition, got: %v", err)
	}
}

func TestInMemoryAttorneys_Update_RefusesUnRetire(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Jane", "TN-1", AttorneyTypeProsecutor))
	r.Retire("bar:1")

	upd := sampleAttorney("bar:1", "Jane", "TN-1", AttorneyTypeProsecutor)
	upd.Status = AttorneyActive
	err := r.Update(upd)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrIllegalAttorneyTransition) {
		t.Errorf("expected ErrIllegalAttorneyTransition, got: %v", err)
	}
	if !strings.Contains(err.Error(), "retired") {
		t.Errorf("error should mention retired: %v", err)
	}
}

// Suspension can be promoted to a terminal — not all transitions
// from suspended are blocked.
func TestInMemoryAttorneys_Suspended_CanGoTerminal(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "Jane", "TN-1", AttorneyTypeProsecutor))
	r.Suspend("bar:1", "ethics")

	// suspended → revoked is permitted (disbarment).
	if err := r.Revoke("bar:1"); err != nil {
		t.Errorf("suspended → revoked must succeed: %v", err)
	}

	// fresh attorney → suspended → retired.
	r.Register(sampleAttorney("bar:2", "Bob", "TN-2", AttorneyTypeProsecutor))
	r.Suspend("bar:2", "leave")
	if err := r.Retire("bar:2"); err != nil {
		t.Errorf("suspended → retired must succeed: %v", err)
	}
}

// ─── List / ListByType ─────────────────────────────────────────────

func TestInMemoryAttorneys_List_Order(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:C", "C", "TN-C", AttorneyTypeProsecutor))
	r.Register(sampleAttorney("bar:A", "A", "TN-A", AttorneyTypeDefenseCounsel))
	r.Register(sampleAttorney("bar:B", "B", "TN-B", AttorneyTypeProsecutor))

	got := r.List()
	if len(got) != 3 {
		t.Fatalf("len: got %d, want 3", len(got))
	}
	want := []string{"bar:A", "bar:B", "bar:C"}
	for i, w := range want {
		if got[i].ID != w {
			t.Errorf("List[%d]: got %q want %q", i, got[i].ID, w)
		}
	}
}

func TestInMemoryAttorneys_ListByType(t *testing.T) {
	r := NewInMemoryAttorneys()
	r.Register(sampleAttorney("bar:1", "A", "TN-1", AttorneyTypeProsecutor))
	r.Register(sampleAttorney("bar:2", "B", "TN-2", AttorneyTypeDefenseCounsel))
	r.Register(sampleAttorney("bar:3", "C", "TN-3", AttorneyTypeDefenseCounsel))
	r.Register(sampleAttorney("att:gal", "GAL", "", AttorneyTypeGuardianAdLitem))

	defenders := r.ListByType(AttorneyTypeDefenseCounsel)
	if len(defenders) != 2 {
		t.Errorf("defenders len: %d, want 2", len(defenders))
	}
	for _, a := range defenders {
		if a.Type != AttorneyTypeDefenseCounsel {
			t.Errorf("filter leaked type %q", a.Type)
		}
	}

	gals := r.ListByType(AttorneyTypeGuardianAdLitem)
	if len(gals) != 1 || gals[0].ID != "att:gal" {
		t.Errorf("GAL filter drift: %+v", gals)
	}

	none := r.ListByType("wizard")
	if len(none) != 0 {
		t.Errorf("unknown type len: %d, want 0", len(none))
	}
}

// ─── Concurrency ────────────────────────────────────────────────────

func TestInMemoryAttorneys_ConcurrentReadsSafe(t *testing.T) {
	r := NewInMemoryAttorneys()
	for i := 0; i < 16; i++ {
		r.Register(sampleAttorney(
			"bar:"+string(rune('A'+i)),
			"alias-"+string(rune('A'+i)),
			"TN-"+string(rune('A'+i)),
			AttorneyTypeProsecutor))
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = r.Lookup("bar:A")
				_, _ = r.LookupByAlias("alias-A")
				_, _ = r.LookupByBarNumber("TN-A")
				_ = r.List()
				_ = r.ListByType(AttorneyTypeProsecutor)
			}
		}()
	}
	wg.Wait()
}
