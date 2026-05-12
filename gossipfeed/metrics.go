// FILE PATH: gossipfeed/metrics.go
//
// DESCRIPTION:
//
//	Phase 9 — OTel error-dimensionality for the gossip publisher.
//	Trust Alignment 14 ("Strict Error Dimensionality") requires
//	the gossip telemetry to distinguish ErrSignatureInvalid (an
//	active hostile attack) from ErrChainBreak (missing event ID),
//	ErrLamportRegression (clock desync), and ordinary back-pressure
//	drops. This file exposes a JN-side Instruments wrapper that
//	classifies the SDK's gossip errors at emit-time and increments
//	dimensional counters; SRE dashboards consume these counters
//	directly via Prometheus / OTel.
//
//	The instruments are constructed once at boot and threaded
//	through the Publisher via a callback hook so the publisher's
//	hot path stays free of metric overhead when telemetry is not
//	configured.
//
// KEY DEPENDENCIES:
//   - go.opentelemetry.io/otel/metric: counter constructor.
//   - attesta/gossip: ErrSinkQueueFull + the typed error set the
//     SDK surfaces from Broadcast/Append.
package gossipfeed

import (
	"errors"
	"fmt"
	"strings"

	"github.com/clearcompass-ai/attesta/gossip"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// ErrorClass enumerates the JN-side high-level error buckets the
// dashboards alert on. Each maps to a distinct alerting policy:
// ErrorClassSignatureInvalid pages an on-call security engineer,
// the others fire Warning-level SRE alerts.
type ErrorClass string

const (
	// ErrorClassSignatureInvalid: an event's signature failed
	// verification. Indicates an active hostile attack on the
	// gossip channel; the wire is replaying signed-but-tampered
	// payloads. Pages security.
	ErrorClassSignatureInvalid ErrorClass = "signature_invalid"

	// ErrorClassChainBreak: an event reference (parent EventID,
	// or a finding's Bindings hash) names a record the store does
	// not have. Either an out-of-order pull or a peer is gossiping
	// hashes from a different topology.
	ErrorClassChainBreak ErrorClass = "chain_break"

	// ErrorClassLamportRegression: an event's Lamport timestamp
	// went backward for the same originator. Likely clock desync
	// at the originator; never a security event by itself.
	ErrorClassLamportRegression ErrorClass = "lamport_regression"

	// ErrorClassQueueFull: the BufferedSink queue rejected an
	// emit because of back-pressure. Operational only; informs
	// queue-depth alerting.
	ErrorClassQueueFull ErrorClass = "queue_full"

	// ErrorClassOther: every error the JN classifier could not
	// match to one of the above. Dashboards keep a low-priority
	// counter so unanticipated errors are still observable.
	ErrorClassOther ErrorClass = "other"
)

// Instruments is the OTel handle the publisher increments on
// every emit. Constructed once via NewInstruments and threaded
// through the publisher hook (RecordError below); zero-cost when
// nil so production code can do `inst.RecordError(...)` without
// nil checks downstream.
type Instruments struct {
	emits  metric.Int64Counter
	errors metric.Int64Counter
}

// NewInstruments constructs the Phase 9 counters or returns an
// error if the OTel meter rejects either descriptor.
func NewInstruments(meter metric.Meter) (*Instruments, error) {
	emits, err := meter.Int64Counter(
		"judicial_gossipfeed_emits_total",
		metric.WithDescription("Gossip events successfully accepted by the local publisher (per kind)."),
	)
	if err != nil {
		return nil, fmt.Errorf("gossipfeed/metrics: emits counter: %w", err)
	}
	errs, err := meter.Int64Counter(
		"judicial_gossipfeed_errors_total",
		metric.WithDescription("Gossip emit errors classified by ErrorClass (Trust Alignment 14)."),
	)
	if err != nil {
		return nil, fmt.Errorf("gossipfeed/metrics: errors counter: %w", err)
	}
	return &Instruments{emits: emits, errors: errs}, nil
}

// RecordEmit increments the per-kind emit counter on a
// successful Broadcast. Safe to call with a nil receiver
// (no-op).
func (i *Instruments) RecordEmit(kind gossip.Kind) {
	if i == nil || i.emits == nil {
		return
	}
	i.emits.Add(nil, 1, metric.WithAttributes(
		attribute.String("kind", string(kind)),
	))
}

// RecordError classifies err and increments the error counter
// with the matching ErrorClass label. The classifier looks at
// the SDK's typed sentinel errors first (errors.Is) and falls
// back to a string-match against the SDK's documented error
// messages for the dimensions the SDK does not yet export as
// sentinels.
//
// Safe to call with a nil receiver.
func (i *Instruments) RecordError(kind gossip.Kind, err error) {
	if i == nil || i.errors == nil || err == nil {
		return
	}
	class := ClassifyError(err)
	i.errors.Add(nil, 1, metric.WithAttributes(
		attribute.String("kind", string(kind)),
		attribute.String("class", string(class)),
	))
}

// ClassifyError maps an SDK gossip / verifier / cosign error
// into one of the ErrorClass buckets the dashboards alert on.
// Exported so test fixtures and external observability code can
// share the same classifier — Trust Alignment 14 explicitly
// calls for one canonical mapping across the network.
func ClassifyError(err error) ErrorClass {
	if err == nil {
		return ErrorClassOther
	}
	if errors.Is(err, gossip.ErrSinkQueueFull) {
		return ErrorClassQueueFull
	}
	msg := strings.ToLower(err.Error())
	switch {
	case containsAny(msg, "signature", "invalid sig", "verify failed", "cosign verify"):
		return ErrorClassSignatureInvalid
	case containsAny(msg, "chain break", "missing parent", "unknown event id", "chain not contiguous"):
		return ErrorClassChainBreak
	case containsAny(msg, "lamport", "regression", "decreasing timestamp"):
		return ErrorClassLamportRegression
	case containsAny(msg, "queue full", "queue closed", "sink full"):
		return ErrorClassQueueFull
	}
	return ErrorClassOther
}

// containsAny reports whether hay contains any of the needles.
// Small helper used in ClassifyError; pulled out so a future
// upgrade to typed SDK sentinels can replace the substring match
// without touching every call site.
func containsAny(hay string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}
