// PeerLogConfig + GossipIngestConfig.ValidatePeerLogs tests.
//
// Each foreign-network peer log declared by the operator must be
// structurally complete: a misformed entry would fail at runtime in
// ways the operator could not diagnose — silent verification dead-
// ends, mismatched cosign canonical bytes, witness-set lookups
// resolving to the home network. The validator catches every
// misconfiguration at boot, with a self-explanatory error message.
package config

import (
	"errors"
	"strings"
	"testing"
)

// validPeerLog returns a structurally complete PeerLogConfig for
// federal-courts. Tests mutate one field at a time to assert the
// validator rejects the malformed shape with a self-explanatory
// error.
func validPeerLog() PeerLogConfig {
	return PeerLogConfig{
		LogDID:         "did:web:federal-courts.example",
		NetworkID:      strings.Repeat("a", 64), // 64 hex chars
		GossipEndpoint: "https://federal-courts.example/v1/gossip",
		WitnessDIDs: []string{
			"did:key:z6MkfFedeRal1",
			"did:key:z6MkfFedeRal2",
			"did:key:z6MkfFedeRal3",
		},
		QuorumK: 2,
	}
}

// TestPeerLogConfig_Validate_Happy pins the structurally-complete
// case: every required field set, all the way down to QuorumK ≤
// len(WitnessDIDs).
func TestPeerLogConfig_Validate_Happy(t *testing.T) {
	t.Parallel()
	if err := validPeerLog().validate(0); err != nil {
		t.Errorf("baseline good config rejected: %v", err)
	}
}

// TestPeerLogConfig_Validate_Rejections walks every required-field
// mutation and confirms the validator returns ErrInvalidConfig with
// a message that names the offending field.
func TestPeerLogConfig_Validate_Rejections(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		mutate   func(*PeerLogConfig)
		wantSubs string
	}{
		{"empty_LogDID", func(p *PeerLogConfig) { p.LogDID = "" }, "LogDID required"},
		{"empty_GossipEndpoint", func(p *PeerLogConfig) { p.GossipEndpoint = "" }, "GossipEndpoint required"},
		{"empty_NetworkID", func(p *PeerLogConfig) { p.NetworkID = "" }, "NetworkID must be 64 hex chars"},
		{"short_NetworkID", func(p *PeerLogConfig) { p.NetworkID = "abc" }, "NetworkID must be 64 hex chars"},
		{"non_hex_NetworkID", func(p *PeerLogConfig) {
			p.NetworkID = strings.Repeat("z", 64) // 'z' is non-hex
		}, "non-hex character"},
		{"empty_WitnessDIDs", func(p *PeerLogConfig) { p.WitnessDIDs = nil }, "WitnessDIDs required"},
		{"zero_QuorumK", func(p *PeerLogConfig) { p.QuorumK = 0 }, "QuorumK = 0"},
		{"QuorumK_exceeds_witnesses", func(p *PeerLogConfig) { p.QuorumK = 99 }, "QuorumK = 99"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := validPeerLog()
			c.mutate(&p)
			err := p.validate(0)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
			if !strings.Contains(err.Error(), c.wantSubs) {
				t.Errorf("err message %q should mention %q", err.Error(), c.wantSubs)
			}
		})
	}
}

// TestValidatePeerLogs_DuplicateLogDID pins that two PeerLogs sharing
// the same LogDID is a startup-fatal misconfiguration — heads from
// the foreign log would otherwise route into one of two journal
// destinations non-deterministically.
func TestValidatePeerLogs_DuplicateLogDID(t *testing.T) {
	t.Parallel()
	g := GossipIngestConfig{
		PeerLogs: []PeerLogConfig{validPeerLog(), validPeerLog()},
	}
	err := g.ValidatePeerLogs()
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "duplicates LogDID") {
		t.Errorf("err = %q, want a duplicate-LogDID message", err.Error())
	}
}

// TestValidatePeerLogs_DistinctNetworksOK pins the multi-network
// happy path: two PeerLogs with DIFFERENT LogDIDs (federal + GA)
// validate together — the JN can audit references into BOTH foreign
// networks simultaneously.
func TestValidatePeerLogs_DistinctNetworksOK(t *testing.T) {
	t.Parallel()
	g := GossipIngestConfig{
		PeerLogs: []PeerLogConfig{
			validPeerLog(),
			{
				LogDID:         "did:web:ga-courts.example",
				NetworkID:      strings.Repeat("b", 64),
				GossipEndpoint: "https://ga-courts.example/v1/gossip",
				WitnessDIDs:    []string{"did:key:z6MkfGA1", "did:key:z6MkfGA2"},
				QuorumK:        1,
			},
		},
	}
	if err := g.ValidatePeerLogs(); err != nil {
		t.Errorf("two distinct PeerLogs rejected: %v", err)
	}
}

// TestValidatePeerLogs_EmptyOK pins the single-network case: no
// PeerLogs declared is valid (it's the v1.36 baseline; cross-network
// support is opt-in).
func TestValidatePeerLogs_EmptyOK(t *testing.T) {
	t.Parallel()
	g := GossipIngestConfig{}
	if err := g.ValidatePeerLogs(); err != nil {
		t.Errorf("empty PeerLogs should validate: %v", err)
	}
}
