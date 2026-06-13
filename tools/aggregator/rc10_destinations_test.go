/*
tools/aggregator/rc10_destinations_test.go — the rc10 consumer-wave lock
suite (JN#176): W2's two acceptance properties at projection altitude,
the lifecycle refusal taxonomy, fail-closed defaults, and the
all-bundles vocabulary census.

Valid payloads are minted by the SDK's production encoders; entries use
the same minimal envelope recipe the verification package's own suite
blesses. Hand-assembly appears ONLY to prove rejection (the mix-violating
retire), per the testing mandate.
*/
package aggregator

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/exchange"
	"github.com/baseproof/baseproof/kinds"
	libagg "github.com/baseproof/tooling/libs/aggregator"

	deployregistry "github.com/clearcompass-ai/judicial-network/deployments/registry"
)

// ─── fixtures ───────────────────────────────────────────────────────

type fakeStore struct {
	provisions, amends, retires []string // destination refs, in order
	refusal                     string   // scripted refusal for the next Apply
}

func (f *fakeStore) ApplyProvision(_ context.Context, p exchange.DestinationProvision, _ string, _ uint64) (string, error) {
	if f.refusal != "" {
		return f.refusal, nil
	}
	f.provisions = append(f.provisions, p.DestinationRef)
	return "", nil
}
func (f *fakeStore) ApplyAmend(_ context.Context, a exchange.DestinationAmend, _ string, _ uint64) (string, error) {
	if f.refusal != "" {
		return f.refusal, nil
	}
	f.amends = append(f.amends, a.DestinationRef)
	return "", nil
}
func (f *fakeStore) ApplyRetire(_ context.Context, r exchange.DestinationRetire, _ string, _ uint64) (string, error) {
	if f.refusal != "" {
		return f.refusal, nil
	}
	f.retires = append(f.retires, r.DestinationRef)
	return "", nil
}

func (f *fakeStore) mutations() int { return len(f.provisions) + len(f.amends) + len(f.retires) }

// admitAll / rejectAll script the W2 judge verdict; the REAL gate's
// vocabulary + mix behavior is locked one layer down where it lives
// (verification/platform_kind_vocab_test.go — the same CheckCosignature
// the production BundleSubmitGate runs). This suite owns the consumer
// side: verdict → counter → store, nothing half-applied.
type scriptGate struct{ rej *GateRejection }

func (s scriptGate) Admit(_ *envelope.Entry) *GateRejection { return s.rej }

func decodedEntry(t *testing.T, payloadRaw []byte) *libagg.DecodedEntry {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(payloadRaw, &m); err != nil {
		t.Fatalf("payload unmarshal: %v", err)
	}
	return &libagg.DecodedEntry{
		LogDID:   "did:baseproof:log:test",
		Sequence: 42,
		Payload:  m,
		Entry: &envelope.Entry{
			Header:        envelope.ControlHeader{SignerDID: "did:web:clerk.example", Destination: "did:web:state:tn:davidson"},
			DomainPayload: payloadRaw,
			Signatures:    []envelope.Signature{{SignerDID: "did:web:clerk.example"}},
		},
	}
}

func sdkProvision(t *testing.T, ref string) []byte {
	t.Helper()
	raw, err := exchange.EncodeDestinationProvisionPayload(exchange.DestinationProvision{
		DestinationRef: ref, ExchangeDID: "did:web:state:tn:davidson",
		Endpoints: map[string]string{"filing": "https://" + "circuit.example/file"},
	})
	if err != nil {
		t.Fatalf("SDK provision encode: %v", err)
	}
	return raw
}

func sdkRetire(t *testing.T, ref string) []byte {
	t.Helper()
	raw, err := exchange.EncodeDestinationRetirePayload(exchange.DestinationRetire{
		DestinationRef: ref, ExchangeDID: "did:web:state:tn:davidson",
	})
	if err != nil {
		t.Fatalf("SDK retire encode: %v", err)
	}
	return raw
}

func newTestProjector(gate SubmitGater, store DestinationStore) *JudicialProjector {
	p := NewJudicialProjector(nil) // nil *Indexer: platform kinds never touch it (proven below)
	p.Gate = gate
	p.Destinations = store
	return p
}

// ─── classify ───────────────────────────────────────────────────────

func TestClassify_PlatformKinds(t *testing.T) {
	for _, k := range []string{
		kinds.EntryExchangeGenesisV1, kinds.EntryDestinationProvisionV1,
		kinds.EntryDestinationAmendV1, kinds.EntryDestinationRetireV1,
		kinds.EntryDelegationGrantV1, kinds.EntryCredentialAttestationV1,
		kinds.EntryNetworkBurnV1,
	} {
		d := decodedEntry(t, []byte(`{"kind":"`+k+`"}`))
		if got := classify(d).EntryType; got != "platform_kind" {
			t.Fatalf("%s must classify platform_kind, got %q", k, got)
		}
	}
	// A judicial event payload is untouched by the new branch.
	d := decodedEntry(t, []byte(`{"event_type":"case_initiation"}`))
	if got := classify(d).EntryType; got == "platform_kind" {
		t.Fatal("judicial events must not classify as platform_kind")
	}
}

// ─── W2 acceptance #1: the gate-bypass ───────────────────────────────

// TestRC10_GateBypass_DirectoryUnmoved is JN#176's first DoD test: a
// WELL-FORMED retire (the SDK encoder built it; it decodes cleanly) whose
// mix the gate REFUSES — exactly what an attacker POSTing straight to the
// ledger achieves — must leave the directory unmoved and increment the
// NAMED refusal counter. Nothing half-applied.
func TestRC10_GateBypass_DirectoryUnmoved(t *testing.T) {
	store := &fakeStore{}
	p := newTestProjector(scriptGate{rej: &GateRejection{Code: "insufficient_signers", Reason: "1 < 2"}}, store)

	if err := p.Project(context.Background(), decodedEntry(t, sdkRetire(t, "tn/davidson/circuit-1"))); err != nil {
		t.Fatalf("a refused entry is a domain violation, never an error: %v", err)
	}
	if store.mutations() != 0 {
		t.Fatalf("THE KILL TEST: directory moved on a gate-refused retire: %+v", store)
	}
	if got := p.Refusals.Count(RefusalGateRejected); got != 1 {
		t.Fatalf("the named counter must record the bypass attempt: %d", got)
	}
}

// ─── W2 acceptance #2: rogue grant is inert ──────────────────────────

// TestRC10_RogueGrant_Inert: a chain-less DELEGATION-GRANT (well-formed,
// sequenced under open admission) mutates NO view — no directory write, no
// judicial indexing (the nil *Indexer would panic if touched), no counter
// noise. Inert-by-absence until 13b wires chain verification; this test is
// the tripwire that fires the day someone wires it dark.
func TestRC10_RogueGrant_Inert(t *testing.T) {
	store := &fakeStore{}
	p := newTestProjector(scriptGate{}, store) // even an ADMITTING gate
	grant := []byte(`{"kind":"` + kinds.EntryDelegationGrantV1 + `","origin_ref":"o","subject":"s","delegate":"d","role":"rogue"}`)
	if err := p.Project(context.Background(), decodedEntry(t, grant)); err != nil {
		t.Fatalf("inert kind must not error: %v", err)
	}
	if store.mutations() != 0 {
		t.Fatal("a delegation grant mutated the directory")
	}
	for code, n := range p.Refusals.Snapshot() {
		t.Fatalf("inert is not refused: unexpected counter %s=%d", code, n)
	}
	// Credential attestations and burns: same inertness.
	for _, k := range []string{kinds.EntryCredentialAttestationV1, kinds.EntryNetworkBurnV1, kinds.EntryExchangeGenesisV1} {
		if err := p.Project(context.Background(), decodedEntry(t, []byte(`{"kind":"`+k+`"}`))); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
	if store.mutations() != 0 {
		t.Fatal("an inert kind mutated the directory")
	}
}

// ─── the judged lifecycle ────────────────────────────────────────────

func TestRC10_MixPassing_LifecycleApplies(t *testing.T) {
	store := &fakeStore{}
	p := newTestProjector(scriptGate{}, store)
	if err := p.Project(context.Background(), decodedEntry(t, sdkProvision(t, "tn/davidson/circuit-1"))); err != nil {
		t.Fatal(err)
	}
	if err := p.Project(context.Background(), decodedEntry(t, sdkRetire(t, "tn/davidson/circuit-1"))); err != nil {
		t.Fatal(err)
	}
	if len(store.provisions) != 1 || len(store.retires) != 1 {
		t.Fatalf("judged lifecycle must apply: %+v", store)
	}
	if n := len(p.Refusals.Snapshot()); n != 0 {
		t.Fatalf("clean lifecycle must not count refusals: %v", p.Refusals.Snapshot())
	}
}

func TestRC10_LifecyclePollution_NamedRefusals(t *testing.T) {
	store := &fakeStore{refusal: RefusalDuplicateProvision}
	p := newTestProjector(scriptGate{}, store)
	if err := p.Project(context.Background(), decodedEntry(t, sdkProvision(t, "tn/davidson/circuit-1"))); err != nil {
		t.Fatal(err)
	}
	if store.mutations() != 0 {
		t.Fatal("a refused lifecycle op must not mutate")
	}
	if p.Refusals.Count(RefusalDuplicateProvision) != 1 {
		t.Fatalf("lifecycle pollution must count by name: %v", p.Refusals.Snapshot())
	}
}

// ─── fail-closed defaults ────────────────────────────────────────────

func TestRC10_NilGate_FailsClosed(t *testing.T) {
	store := &fakeStore{}
	p := newTestProjector(nil, store)
	if err := p.Project(context.Background(), decodedEntry(t, sdkProvision(t, "tn/davidson/circuit-1"))); err != nil {
		t.Fatal(err)
	}
	if store.mutations() != 0 {
		t.Fatal("no judge wired ⇒ the directory must never move")
	}
	if p.Refusals.Count(RefusalGateUnwired) != 1 {
		t.Fatalf("the unwired judge must be counted by name: %v", p.Refusals.Snapshot())
	}
}

func TestRC10_MalformedDestinationPayload_CountedNotApplied(t *testing.T) {
	store := &fakeStore{}
	p := newTestProjector(scriptGate{}, store)
	bad := []byte(`{"kind":"` + kinds.EntryDestinationProvisionV1 + `","destination_ref":""}`)
	if err := p.Project(context.Background(), decodedEntry(t, bad)); err != nil {
		t.Fatal(err)
	}
	if store.mutations() != 0 || p.Refusals.Count(RefusalMalformed) != 1 {
		t.Fatalf("malformed must count, never apply: %+v %v", store, p.Refusals.Snapshot())
	}
}

// ─── the convergence census ──────────────────────────────────────────

// TestRC10_Census_EveryBundleSpeaksThePlatformKinds is the machine-checked
// adoption proof: EVERY registered deployment bundle's cosignature policy
// names all four destination/exchange kinds, and its prerequisite policy
// knows them. A new deployment that forgets the platformkinds rows fails
// here, not in production.
func TestRC10_Census_EveryBundleSpeaksThePlatformKinds(t *testing.T) {
	bundles := deployregistry.LoadAll()
	if len(bundles) == 0 {
		t.Fatal("no bundles registered — census vacuous")
	}
	wantKinds := []string{
		kinds.EntryExchangeGenesisV1,
		kinds.EntryDestinationProvisionV1,
		kinds.EntryDestinationAmendV1,
		kinds.EntryDestinationRetireV1,
	}
	for _, b := range bundles {
		for _, k := range wantKinds {
			if _, err := b.CosignaturePolicy().Lookup(k); err != nil {
				t.Errorf("bundle %s: cosignature policy missing %s: %v", b.ExchangeDID(), k, err)
			}
			if !b.PrerequisitePolicy().KnowsEventType(k) {
				t.Errorf("bundle %s: prerequisite vocabulary missing %s", b.ExchangeDID(), k)
			}
		}
	}
}
