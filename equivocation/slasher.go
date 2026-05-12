// FILE PATH: equivocation/slasher.go
//
// DESCRIPTION:
//
//	Phase 5 — Slasher. Consumes verified equivocation findings
//	pulled from the gossip feed and updates per-ledger trust
//	state (a SlashRegistry). Once a ledger's slash count crosses
//	the configured threshold, its voting weight in
//	consortium/membership decisions drops to zero until the
//	consortium publishes a rehabilitation rotation.
//
//	The slasher is the read-side complement to scanner.go's
//	emit-side: scanner detects, slasher penalizes. Splitting
//	them lets independent auditor nodes (who do not write to
//	the local gossip store) participate just as effectively as
//	the JN API process.
//
//	Trust Alignment 7: "Deterministic Equivocation Detection
//	— permanently slashing the Ledger's trust score."
//
// KEY DEPENDENCIES:
//   - attesta/gossip/findings: EquivocationFinding (the wrapped
//     equivocation proof that gossip transports)
//   - attesta/crypto/cosign: WitnessKeySet (the per-ledger
//     witness topology used to verify findings on read)
package equivocation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/clearcompass-ai/attesta/crypto/cosign"
	"github.com/clearcompass-ai/attesta/gossip/findings"
)

// ErrSlasherConfig is returned by NewSlasher for malformed
// configuration.
var ErrSlasherConfig = errors.New("equivocation/slasher: invalid configuration")

// SlashState describes a single ledger's penalty record. The
// public surface lets consortium/membership.go decide voting
// weight by Slashed; Audit fields are for SRE telemetry.
type SlashState struct {
	LedgerEndpoint string
	Count          int
	FirstSeen      time.Time
	LastSeen       time.Time
	Slashed        bool
}

// SlasherConfig configures the slasher.
type SlasherConfig struct {
	// WitnessSets is keyed by the same logDID embedded in the
	// finding's Proof.HeadA.RootHash binding. The slasher uses
	// this to re-verify each finding before applying the penalty —
	// trusting only the cryptography, never the wire.
	WitnessSets map[string]*cosign.WitnessKeySet

	// Threshold is the number of distinct verified findings
	// against the same ledger that triggers slashing. Default 1
	// (any verified equivocation is unforgeable; a single proof
	// suffices). Operators may set higher thresholds for
	// jurisdictions with explicit "two-strike" governance.
	Threshold int

	// Logger is the structured logger; nil → slog.Default.
	Logger *slog.Logger
}

// Slasher tracks per-ledger penalty state.
type Slasher struct {
	cfg       SlasherConfig
	logger    *slog.Logger
	threshold int

	mu    sync.RWMutex
	state map[string]*SlashState // keyed by LedgerEndpoint
}

// NewSlasher returns a slasher ready to receive findings.
func NewSlasher(cfg SlasherConfig) (*Slasher, error) {
	if len(cfg.WitnessSets) == 0 {
		return nil, fmt.Errorf("%w: empty WitnessSets", ErrSlasherConfig)
	}
	threshold := cfg.Threshold
	if threshold < 1 {
		threshold = 1
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Slasher{
		cfg:       cfg,
		logger:    logger,
		threshold: threshold,
		state:     make(map[string]*SlashState),
	}, nil
}

// Apply re-verifies and records the finding. Returns nil iff the
// finding is cryptographically valid AND was successfully
// applied. The slasher trusts only the SDK's Verify(set) check —
// findings that fail verification are dropped silently so a
// hostile gossip peer cannot fabricate slashes by emitting
// signed-but-bogus findings.
func (s *Slasher) Apply(_ context.Context, finding *findings.EquivocationFinding) error {
	if s == nil {
		return errors.New("equivocation/slasher: nil receiver")
	}
	if finding == nil {
		return errors.New("equivocation/slasher: nil finding")
	}
	// Use the ledger endpoint embedded in the finding as the
	// trust-state key. Each finding's proof contains the witness
	// signatures from one ledger; if multiple ledgers happened to
	// equivocate on the same TreeSize, each maintains its own
	// state.
	endpoint := finding.LedgerEndpoint
	if endpoint == "" {
		return errors.New("equivocation/slasher: finding has empty LedgerEndpoint")
	}
	// Re-verify against ANY of the configured witness sets — a
	// production deployment scopes WitnessSets by source-log DID,
	// but the finding only carries the endpoint URL. We pick the
	// set whose Verify succeeds; if none does, the finding is
	// dropped.
	verified := s.tryVerify(finding)
	if !verified {
		s.logger.Warn("equivocation/slasher: finding failed re-verification; dropped",
			slog.String("ledger_endpoint", endpoint),
		)
		return nil
	}
	now := time.Now().UTC()
	s.mu.Lock()
	state, ok := s.state[endpoint]
	if !ok {
		state = &SlashState{LedgerEndpoint: endpoint, FirstSeen: now}
		s.state[endpoint] = state
	}
	state.Count++
	state.LastSeen = now
	if state.Count >= s.threshold && !state.Slashed {
		state.Slashed = true
		s.logger.Error("equivocation/slasher: ledger SLASHED",
			slog.String("ledger_endpoint", endpoint),
			slog.Int("count", state.Count),
			slog.Int("threshold", s.threshold),
		)
	}
	s.mu.Unlock()
	return nil
}

// tryVerify walks the configured witness sets and returns true on
// the first successful Verify. The slasher accepts the finding
// once any source-log topology validates it.
func (s *Slasher) tryVerify(finding *findings.EquivocationFinding) bool {
	for _, set := range s.cfg.WitnessSets {
		if set == nil {
			continue
		}
		if err := finding.Verify(set); err == nil {
			return true
		}
	}
	return false
}

// IsSlashed reports whether the named ledger has been slashed.
// Used by consortium/membership.go to zero out the ledger's
// voting weight in quorum decisions.
func (s *Slasher) IsSlashed(ledgerEndpoint string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.state[ledgerEndpoint]
	return ok && st.Slashed
}

// Snapshot returns a deep copy of the current slash state. Used
// by /v1/judicial/monitoring/slash-state for ops dashboards.
func (s *Slasher) Snapshot() []SlashState {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SlashState, 0, len(s.state))
	for _, st := range s.state {
		out = append(out, *st)
	}
	return out
}

// Reset zeroes the slash state for one ledger. The consortium
// governance flow uses this after a successful rehabilitation
// rotation (PurposeRotation evidence signed by the existing
// quorum). Hidden behind explicit consortium policy — never
// triggered automatically.
func (s *Slasher) Reset(ledgerEndpoint string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state, ledgerEndpoint)
	s.logger.Info("equivocation/slasher: state reset (post-rotation rehabilitation)",
		slog.String("ledger_endpoint", ledgerEndpoint),
	)
}
