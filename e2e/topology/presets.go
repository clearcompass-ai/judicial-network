package topology

import (
	"fmt"
	"sort"
)

// preset builds a named StackSpec. Adding a topology is one entry in the registry
// below — the builder needs no new code.
type preset func() StackSpec

var presets = map[string]preset{
	"single":     single,
	"federation": federation,
	"mega":       mega,
}

// Names returns the registered preset names, sorted.
func Names() []string {
	out := make([]string, 0, len(presets))
	for k := range presets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Get resolves a preset by name and validates it.
func Get(name string) (StackSpec, error) {
	p, ok := presets[name]
	if !ok {
		return StackSpec{}, fmt.Errorf("unknown preset %q; known: %v", name, Names())
	}
	s := p()
	if err := s.Validate(); err != nil {
		return StackSpec{}, fmt.Errorf("preset %q: %w", name, err)
	}
	return s, nil
}

// single — one network; the ledger throughput / audit baseline (no aggregator).
func single() StackSpec {
	return StackSpec{
		Name: "single",
		Networks: []NetworkSpec{
			{
				Name: "n1", QuorumK: 2, Witnesses: 3, Auditors: 2,
				HasJN: true, HasAggregator: false,
				Destinations: []string{"did:web:state:tn:davidson"},
			},
		},
		Tuning: DefaultTuning(),
	}
}

// federation — the three-network baseline the cross-network JN scenarios run on.
func federation() StackSpec {
	return StackSpec{
		Name: "federation",
		Networks: []NetworkSpec{
			{
				Name: "federal", QuorumK: 3, Witnesses: 4, Auditors: 3,
				HasJN: true, HasAggregator: true,
				Destinations: []string{"scotus", "ca6", "tnmd"},
			},
			{
				Name: "tn", QuorumK: 2, Witnesses: 3, Auditors: 3,
				HasJN: true, HasAggregator: true,
				Destinations: []string{"tnsc", "tnca", "davidson"},
			},
			{
				Name: "ca", QuorumK: 2, Witnesses: 3, Auditors: 3,
				HasJN: true, HasAggregator: true,
				Destinations: []string{"casc", "ca4", "ca6d", "riverside", "santaclara"},
			},
		},
		SharedWitnesses: 2,
		SharedAuditors:  2,
		Tuning:          DefaultTuning(),
	}
}

// mega — 5 networks × 20 witnesses / 20 auditors; the scale-out example. Adding a
// topology of any size is exactly this shape: data, not a new bring-up path.
func mega() StackSpec {
	nets := make([]NetworkSpec, 0, 5)
	for i := 1; i <= 5; i++ {
		nets = append(nets, NetworkSpec{
			Name: fmt.Sprintf("n%d", i), QuorumK: 7, Witnesses: 20, Auditors: 20,
			HasJN: true, HasAggregator: true,
		})
	}
	return StackSpec{
		Name: "mega", Networks: nets,
		SharedWitnesses: 2, SharedAuditors: 2,
		Tuning: DefaultTuning(),
	}
}

// FromFlags builds an ad-hoc N-identical-network topology, e.g.
//
//	e2e up --networks 5 --witnesses 20 --auditors 20 --k 7
func FromFlags(networks, witnesses, auditors, quorumK int) (StackSpec, error) {
	if networks < 1 {
		return StackSpec{}, fmt.Errorf("--networks must be >= 1 (got %d)", networks)
	}
	nets := make([]NetworkSpec, 0, networks)
	for i := 1; i <= networks; i++ {
		nets = append(nets, NetworkSpec{
			Name: fmt.Sprintf("n%d", i), QuorumK: quorumK, Witnesses: witnesses, Auditors: auditors,
			HasJN: true, HasAggregator: networks > 1,
		})
	}
	s := StackSpec{Name: "adhoc", Networks: nets, Tuning: DefaultTuning()}
	if err := s.Validate(); err != nil {
		return StackSpec{}, err
	}
	return s, nil
}
