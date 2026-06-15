package scenario

// The principal registry: the deterministic roster of cryptographic identities
// for one jurisdiction. Every officer (adjudicator, clerk), every attorney, and
// the institutional root is a Principal with a stable DID + signing key derived
// from (masterSeed, label) — so a seeded run is reproducible and a re-run
// provisions the same people onto the same DIDs.
//
// The registry is the bridge between the WHO (the scenario data model:
// Jurisdiction/Court/Division/Adjudicator/Bar) and the cryptographic substrate
// the seeder + generators drive (DIDs, keys, on-log delegation positions). It
// holds no policy — the catalog role names come straight from the model.

import (
	"encoding/binary"
	"fmt"

	"github.com/baseproof/tooling/libs/auth/identity"
	"github.com/clearcompass-ai/judicial-network/schemas"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// PrincipalKind classifies a registry entry by its role in the population.
type PrincipalKind string

const (
	// KindInstitutional is the depth-0 granter root (the court's own DID).
	KindInstitutional PrincipalKind = "institutional"
	// KindAdjudicator is a delegated signer judge/justice/chief.
	KindAdjudicator PrincipalKind = "adjudicator"
	// KindClerk is a delegated signer court clerk.
	KindClerk PrincipalKind = "clerk"
	// KindAttorney is a FILER principal — NOT a delegated signer. Files under
	// FiledByCapacity carrying a (public, plaintext) bar number.
	KindAttorney PrincipalKind = "attorney"
)

// Principal is one cryptographic identity in the population.
type Principal struct {
	Name      string
	Kind      PrincipalKind
	Role      string // catalog signer role (adjudicator/clerk); "" otherwise
	Title     string // human title (adjudicator); "" otherwise
	Court     string // owning court name (adjudicator/clerk); "" otherwise
	FilerRole string // attorney filer role; "" otherwise
	BPR       string // attorney TN bar number (public, plaintext); "" otherwise
	DID       string

	priv *secp256k1.PrivateKey

	// Delegation is the on-log position of this principal's delegation entry,
	// assigned by Seed. nil until seeded; always nil for the institutional root
	// (depth-0 granter, not itself delegated) and attorneys (filers, not
	// delegated signers).
	Delegation *schemas.LogPositionRef
}

// Registry is the deterministic roster for one jurisdiction.
type Registry struct {
	Jurisdiction  Jurisdiction
	Institutional *Principal
	Officers      []*Principal // adjudicators (deduped) then clerks — seed order
	Attorneys     []*Principal

	byDID map[string]*Principal
}

// BuildRegistry derives the full deterministic roster for j under masterSeed.
// Pure function of its inputs: same (j, masterSeed) ⇒ identical DIDs, keys, and
// bar numbers every time.
func BuildRegistry(j Jurisdiction, masterSeed []byte) *Registry {
	r := &Registry{Jurisdiction: j, byDID: map[string]*Principal{}}

	// Institutional root: signs depth-0 grants. Its DID is the court's own
	// institutional DID (a did:web), NOT a derived did:key; the derived key is
	// its default signing key (the live path rebinds the genesis key to the
	// same DID).
	instID := deriveIdentity(masterSeed, "institutional|"+j.InstitutionalDID)
	r.Institutional = &Principal{
		Name: j.Name + " (institutional)",
		Kind: KindInstitutional,
		DID:  j.InstitutionalDID,
		priv: instID.Priv,
	}
	r.index(r.Institutional)

	// Adjudicators: deduped by name across every court/division (a judge sitting
	// in two divisions is ONE identity holding ONE delegation). First occurrence
	// fixes the owning court and preserves a stable seed order.
	seen := map[string]bool{}
	for _, c := range j.Courts {
		for _, d := range c.Divisions {
			for _, a := range d.Bench {
				if seen[a.Name] {
					continue
				}
				seen[a.Name] = true
				id := deriveIdentity(masterSeed, "adjudicator|"+j.Key+"|"+a.Name)
				p := &Principal{
					Name: a.Name, Kind: KindAdjudicator, Role: a.Role, Title: a.Title,
					Court: c.Name, DID: id.DID, priv: id.Priv,
				}
				r.Officers = append(r.Officers, p)
				r.index(p)
			}
		}
	}

	// Clerks: one or more per court (Clerk.Clerks, default 1).
	for _, c := range j.Courts {
		n := c.Clerk.Clerks
		if n < 1 {
			n = 1
		}
		for i := 0; i < n; i++ {
			name := c.Clerk.Name
			if n > 1 {
				name = fmt.Sprintf("%s #%d", c.Clerk.Name, i+1)
			}
			id := deriveIdentity(masterSeed, fmt.Sprintf("clerk|%s|%s|%d", j.Key, c.Name, i))
			p := &Principal{
				Name: name, Kind: KindClerk, Role: j.ClerkRole,
				Court: c.Name, DID: id.DID, priv: id.Priv,
			}
			r.Officers = append(r.Officers, p)
			r.index(p)
		}
	}

	// Attorneys: FILER principals. Each gets a key, a did:key, a filer role
	// (round-robin over the bar's roles), and a public TN bar number.
	for i := 0; i < j.Bar.Count; i++ {
		filer := ""
		if len(j.Bar.Roles) > 0 {
			filer = j.Bar.Roles[i%len(j.Bar.Roles)]
		}
		id := deriveIdentity(masterSeed, fmt.Sprintf("attorney|%s|%d", j.Key, i))
		p := &Principal{
			Name:      fmt.Sprintf("%s Bar Member %d", j.Name, i+1),
			Kind:      KindAttorney,
			FilerRole: filer,
			BPR:       deriveBPR(masterSeed, j.Key, i),
			DID:       id.DID,
			priv:      id.Priv,
		}
		r.Attorneys = append(r.Attorneys, p)
		r.index(p)
	}

	return r
}

func (r *Registry) index(p *Principal) {
	if r.byDID == nil {
		r.byDID = map[string]*Principal{}
	}
	r.byDID[p.DID] = p
}

// ByDID returns the principal with the given DID, or nil.
func (r *Registry) ByDID(did string) *Principal { return r.byDID[did] }

// Adjudicators returns the deduped delegated judges/justices.
func (r *Registry) Adjudicators() []*Principal {
	return r.officersOfKind(KindAdjudicator)
}

// Clerks returns the delegated court clerks.
func (r *Registry) Clerks() []*Principal {
	return r.officersOfKind(KindClerk)
}

func (r *Registry) officersOfKind(k PrincipalKind) []*Principal {
	var out []*Principal
	for _, p := range r.Officers {
		if p.Kind == k {
			out = append(out, p)
		}
	}
	return out
}

// BindKeys binds every principal's (DID → signing key) into sp so the
// IdentityProvider can sign on their behalf. In production the institutional
// key is the genesis key and officer keys live in their wallets; this is the
// local/dev binding that makes the whole population signable in one process.
func (r *Registry) BindKeys(sp *identity.StubProvider) {
	sp.BindKey(r.Institutional.DID, r.Institutional.priv)
	for _, p := range r.Officers {
		sp.BindKey(p.DID, p.priv)
	}
	for _, p := range r.Attorneys {
		sp.BindKey(p.DID, p.priv)
	}
}

// deriveBPR produces a stable 6-digit TN bar number for attorney i. Derived
// from the same seed so a run is reproducible; the value is public (it rides
// FiledByCapacity in plaintext), so no secrecy is required.
func deriveBPR(masterSeed []byte, jKey string, i int) string {
	s := deriveScalar(masterSeed, fmt.Sprintf("bpr|%s|%d", jKey, i), 0)
	n := binary.BigEndian.Uint32(s[:4])%900000 + 100000 // 100000..999999
	return fmt.Sprintf("%06d", n)
}
