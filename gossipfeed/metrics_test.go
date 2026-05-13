// FILE PATH: gossipfeed/metrics_test.go
//
// Tests for the Phase 9 OTel error-dimensionality classifier
// (Trust Alignment 14). The classifier is the only public
// surface that has stable semantics worth testing
// independently of the OTel meter — the counter wiring itself
// is a thin pass-through to the SDK.
//
//  1. ClassifyError returns ErrorClassOther for nil input.
//  2. ClassifyError maps gossip.ErrSinkQueueFull to
//     ErrorClassQueueFull via errors.Is.
//  3. Substring classification: "signature invalid" →
//     SignatureInvalid; "chain break" → ChainBreak;
//     "lamport regression" → LamportRegression.
//  4. Unmatched errors return ErrorClassOther (low-priority
//     bucket).
//  5. nil-receiver RecordEmit / RecordError are no-ops (callers
//     can pre-emptively wire Instruments without a meter
//     configured in dev / test).
package gossipfeed

import (
	"errors"
	"fmt"
	"testing"

	"github.com/clearcompass-ai/attesta/gossip"
)

func TestClassifyError_NilReturnsOther(t *testing.T) {
	if got := ClassifyError(nil); got != ErrorClassOther {
		t.Fatalf("ClassifyError(nil) = %q, want %q", got, ErrorClassOther)
	}
}

func TestClassifyError_QueueFull_ViaErrorsIs(t *testing.T) {
	err := fmt.Errorf("publisher: %w", gossip.ErrSinkQueueFull)
	if got := ClassifyError(err); got != ErrorClassQueueFull {
		t.Fatalf("wrapped ErrSinkQueueFull = %q, want %q", got, ErrorClassQueueFull)
	}
}

func TestClassifyError_SignatureInvalid(t *testing.T) {
	cases := []string{
		"signature verification failed",
		"invalid sig from peer",
		"cosign verify: quorum not reached",
	}
	for _, msg := range cases {
		if got := ClassifyError(errors.New(msg)); got != ErrorClassSignatureInvalid {
			t.Errorf("%q = %q, want %q", msg, got, ErrorClassSignatureInvalid)
		}
	}
}

func TestClassifyError_ChainBreak(t *testing.T) {
	cases := []string{
		"chain break at event 0xabcd",
		"missing parent event_id",
		"unknown event id 0xfeed",
		"chain not contiguous",
	}
	for _, msg := range cases {
		if got := ClassifyError(errors.New(msg)); got != ErrorClassChainBreak {
			t.Errorf("%q = %q, want %q", msg, got, ErrorClassChainBreak)
		}
	}
}

func TestClassifyError_LamportRegression(t *testing.T) {
	cases := []string{
		"lamport timestamp went backward",
		"clock regression detected",
		"decreasing timestamp from originator",
	}
	for _, msg := range cases {
		if got := ClassifyError(errors.New(msg)); got != ErrorClassLamportRegression {
			t.Errorf("%q = %q, want %q", msg, got, ErrorClassLamportRegression)
		}
	}
}

func TestClassifyError_OtherForUnknown(t *testing.T) {
	cases := []string{
		"some unanticipated infrastructure failure",
		"goroutine panic recovered",
	}
	for _, msg := range cases {
		if got := ClassifyError(errors.New(msg)); got != ErrorClassOther {
			t.Errorf("%q = %q, want %q (low-priority bucket)", msg, got, ErrorClassOther)
		}
	}
}

func TestNilInstruments_NoOps(t *testing.T) {
	var inst *Instruments
	// Both methods must be safe on a nil receiver so production
	// hot paths don't need to nil-check before recording.
	inst.RecordEmit(gossip.KindCosignedTreeHead)
	inst.RecordError(gossip.KindEquivocationFinding, errors.New("anything"))
}

func TestErrorClassValues_AreStable(t *testing.T) {
	// Dashboard panels query on these exact strings. The test
	// fails if they ever change without coordinated dashboard
	// updates.
	want := []ErrorClass{
		"signature_invalid",
		"chain_break",
		"lamport_regression",
		"queue_full",
		"other",
	}
	got := []ErrorClass{
		ErrorClassSignatureInvalid,
		ErrorClassChainBreak,
		ErrorClassLamportRegression,
		ErrorClassQueueFull,
		ErrorClassOther,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ErrorClass constants drifted at idx %d: want %q got %q",
				i, want[i], got[i])
		}
	}
}
