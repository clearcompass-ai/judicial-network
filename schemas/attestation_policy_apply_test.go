/*
FILE PATH: schemas/attestation_policy_apply_test.go

DESCRIPTION:

	Unit tests for SetAttestationPolicy. The helper is a guarded
	mutator on envelope.Entry.Header.AttestationPolicyName; the
	tests pin the four guard cases (nil entry, nil pointer, empty
	string, valid name) so any future refactor can't silently
	regress the "byte-stable when not opted in" invariant.
*/
package schemas

import (
	"testing"

	"github.com/clearcompass-ai/attesta/core/envelope"
)

// TestSetAttestationPolicy_NilEntry — calling on a nil entry is a
// no-op (no panic, no allocation). Helps the helper compose with
// builder error paths that might surface nil entries.
func TestSetAttestationPolicy_NilEntry(t *testing.T) {
	name := "x"
	SetAttestationPolicy(nil, &name)
	// No panic = pass.
}

// TestSetAttestationPolicy_NilPointer — nil policyName means "no
// policy"; entry.Header.AttestationPolicyName must stay nil.
func TestSetAttestationPolicy_NilPointer(t *testing.T) {
	entry := &envelope.Entry{Header: envelope.ControlHeader{}}
	SetAttestationPolicy(entry, nil)
	if entry.Header.AttestationPolicyName != nil {
		t.Errorf("AttestationPolicyName = %v, want nil",
			*entry.Header.AttestationPolicyName)
	}
}

// TestSetAttestationPolicy_EmptyString — empty string is treated
// the same as nil (no policy adopted). Keeps the wire shape
// byte-stable when callers pass an empty config field.
func TestSetAttestationPolicy_EmptyString(t *testing.T) {
	entry := &envelope.Entry{Header: envelope.ControlHeader{}}
	empty := ""
	SetAttestationPolicy(entry, &empty)
	if entry.Header.AttestationPolicyName != nil {
		t.Errorf("AttestationPolicyName = %q on empty-string input, want nil",
			*entry.Header.AttestationPolicyName)
	}
}

// TestSetAttestationPolicy_AppliesName — a valid name lands on the
// header as a fresh pointer (not the caller's input pointer — we
// copy the string so the caller's variable can be reused).
func TestSetAttestationPolicy_AppliesName(t *testing.T) {
	entry := &envelope.Entry{Header: envelope.ControlHeader{}}
	name := PolicySealingOrderConcurrence
	SetAttestationPolicy(entry, &name)
	if entry.Header.AttestationPolicyName == nil {
		t.Fatalf("AttestationPolicyName = nil, want %q", name)
	}
	if got := *entry.Header.AttestationPolicyName; got != name {
		t.Errorf("AttestationPolicyName = %q, want %q", got, name)
	}
	// Ensure the helper copies the string — mutating the caller's
	// variable must NOT change the header.
	name = "different"
	if got := *entry.Header.AttestationPolicyName; got != PolicySealingOrderConcurrence {
		t.Errorf("AttestationPolicyName = %q, want %q (helper didn't copy the string)",
			got, PolicySealingOrderConcurrence)
	}
}

// TestSetAttestationPolicy_Idempotent — calling twice with the
// same name leaves the header unchanged (no double-set surprises).
func TestSetAttestationPolicy_Idempotent(t *testing.T) {
	entry := &envelope.Entry{Header: envelope.ControlHeader{}}
	name := PolicyDelegationBoardConcurrence
	SetAttestationPolicy(entry, &name)
	SetAttestationPolicy(entry, &name)
	if entry.Header.AttestationPolicyName == nil ||
		*entry.Header.AttestationPolicyName != name {
		t.Errorf("idempotent set failed; got header = %v",
			entry.Header.AttestationPolicyName)
	}
}
