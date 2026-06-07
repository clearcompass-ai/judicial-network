// Package topology describes a baseproof e2e stack as DATA.
//
// A StackSpec is a set of NetworkSpec (each with its quorum K and witness/auditor
// counts) plus the identities that span networks and the throughput tuning. One
// builder realises any spec, so a new shape — 1 network, 3, or 5×20 — is a preset
// entry (see presets.go) or a set of `--networks/--witnesses/--auditors/--k`
// flags, never a new bring-up code path.
package topology

import "fmt"

// NetworkSpec is one network in a stack: its witnesses, auditors, quorum, the
// destinations (court DIDs) it serves, and whether it fronts a JN enforcer /
// aggregator.
type NetworkSpec struct {
	Name          string
	QuorumK       int
	Witnesses     int
	Auditors      int
	Destinations  []string
	HasJN         bool
	HasAggregator bool
}

func (n NetworkSpec) validate() error {
	if n.Name == "" {
		return fmt.Errorf("network: name required")
	}
	if n.Witnesses < 1 {
		return fmt.Errorf("network %q: needs >= 1 witness", n.Name)
	}
	if n.QuorumK < 1 || n.QuorumK > n.Witnesses {
		return fmt.Errorf("network %q: need 1 <= quorum_k(%d) <= witnesses(%d)",
			n.Name, n.QuorumK, n.Witnesses)
	}
	if n.Auditors < 0 {
		return fmt.Errorf("network %q: auditors must be >= 0", n.Name)
	}
	return nil
}

// Tuning carries the admission/proof/throughput knobs the builder threads into the
// ledger. The zero value is filled by DefaultTuning.
type Tuning struct {
	Admission            string // "credits" | "pow"
	ProofSource          string // "tiles" | "pg" | "shadow"
	BatchSize            int    // 0 ⇒ ledger default
	PGMaxConns           int    // 0 ⇒ ledger default
	SequencerMaxInflight int    // 0 ⇒ ledger default
	WALRetentionBuffer   uint64 // shipped-entry WAL GC margin in sequences; 0 ⇒ GC off (the default)
}

// DefaultTuning is the throughput baseline: fast (credit) admission, proofs served
// from the durable tile substrate.
func DefaultTuning() Tuning {
	return Tuning{Admission: "credits", ProofSource: "tiles"}
}

// StackSpec is a full topology — the unit `e2e up` realises and persists.
type StackSpec struct {
	Name            string
	Networks        []NetworkSpec
	SharedWitnesses int // identities that cosign on EVERY network
	SharedAuditors  int // identities that gossip on EVERY network
	Tuning          Tuning
}

// Validate checks the spec is internally consistent.
func (s StackSpec) Validate() error {
	if len(s.Networks) == 0 {
		return fmt.Errorf("stack %q: at least one network required", s.Name)
	}
	seen := make(map[string]bool, len(s.Networks))
	minW, minA := -1, -1
	for _, n := range s.Networks {
		if err := n.validate(); err != nil {
			return err
		}
		if seen[n.Name] {
			return fmt.Errorf("stack %q: duplicate network name %q", s.Name, n.Name)
		}
		seen[n.Name] = true
		if minW < 0 || n.Witnesses < minW {
			minW = n.Witnesses
		}
		if minA < 0 || n.Auditors < minA {
			minA = n.Auditors
		}
	}
	if s.SharedWitnesses < 0 || s.SharedWitnesses > minW {
		return fmt.Errorf("stack %q: shared_witnesses(%d) must be in [0, %d] (the smallest network's witnesses)",
			s.Name, s.SharedWitnesses, minW)
	}
	if s.SharedAuditors < 0 || s.SharedAuditors > minA {
		return fmt.Errorf("stack %q: shared_auditors(%d) must be in [0, %d] (the smallest network's auditors)",
			s.Name, s.SharedAuditors, minA)
	}
	return nil
}

// NetworkCount, TotalWitnesses, TotalAuditors are convenience totals for the
// builder, the status view, and capacity planning.
func (s StackSpec) NetworkCount() int { return len(s.Networks) }

func (s StackSpec) TotalWitnesses() int {
	t := 0
	for _, n := range s.Networks {
		t += n.Witnesses
	}
	return t
}

func (s StackSpec) TotalAuditors() int {
	t := 0
	for _, n := range s.Networks {
		t += n.Auditors
	}
	return t
}

// Summary is a one-line description for logs and `e2e list`.
func (s StackSpec) Summary() string {
	return fmt.Sprintf("%s: %d network(s), %d witnesses, %d auditors",
		s.Name, s.NetworkCount(), s.TotalWitnesses(), s.TotalAuditors())
}
