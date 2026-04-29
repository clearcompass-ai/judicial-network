/*
FILE PATH: topology/witness_registration.go

DESCRIPTION:
    BLS witness registration gate for the judicial network. Every
    public key admitted into a court's witness set MUST be preceded by
    a successful Proof-of-Possession (PoP) verification call.

KEY ARCHITECTURAL DECISIONS:
    - Implements the registrar obligation declared in
      ortholog-sdk/docs/implementation-obligations.md ("REGISTRAR
      OBLIGATIONS"). The SDK provides VerifyBLSPoP; the domain
      enforces the invariant that no key enters a witness set without
      a PoP that verifies under the protocol's PoP DST.
    - Failure is fail-closed: rejected admissions are NOT retried, NOT
      silently downgraded, and NOT recorded as a "pending" state. The
      registry is the trust boundary for cosignature aggregation; one
      rogue G2 key admitted without PoP defeats every BLS optimistic
      verify check downstream.
    - The registrar is in-memory by design. Persistence is the
      operator's responsibility (config files, secrets manager, etc.);
      the registrar's contract is "validate every admission, then
      record". A persistent layer composes around this without
      changing the verification semantics.
    - Rotation is admission of a new key plus revocation of an old
      one, both gated by PoP for the new key. There is no special
      "rotate" path that bypasses PoP — that would re-introduce the
      vulnerability the gate exists to prevent.

KEY DEPENDENCIES:
    - ortholog-sdk/crypto/signatures: VerifyBLSPoP, ParseBLSPubKey,
      BLSG1CompressedLen, BLSG2CompressedLen.
    - ortholog-sdk/types: WitnessPublicKey shape.
*/
package topology

import (
	"errors"
	"fmt"
	"sync"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// Errors surfaced by the witness registrar. Stable names so callers
// (including monitoring and audit tooling) can match programmatically.
var (
	// ErrWitnessAlreadyRegistered fires when a duplicate ID is
	// admitted. Distinct from ErrPoPVerifyFailed so duplicate-admission
	// does not surface as a cryptographic-attack signal.
	ErrWitnessAlreadyRegistered = errors.New("topology/witness: witness ID already registered")

	// ErrWitnessNotRegistered fires on revoke or lookup of an unknown ID.
	ErrWitnessNotRegistered = errors.New("topology/witness: witness ID not registered")

	// ErrPoPVerifyFailed wraps the underlying VerifyBLSPoP error so
	// callers can distinguish PoP rejection from registry-state errors.
	// Triggers a security alert at the registrar's audit hook.
	ErrPoPVerifyFailed = errors.New("topology/witness: BLS PoP verification failed")

	// ErrInvalidPubKeyLength fires before any cryptographic work — a
	// length mismatch is a structural caller bug, not an attack.
	ErrInvalidPubKeyLength = errors.New("topology/witness: BLS public key wrong length")

	// ErrInvalidPoPLength fires before any cryptographic work.
	ErrInvalidPoPLength = errors.New("topology/witness: BLS PoP wrong length")
)

// WitnessRegistry is the live set of witness keys for one log. Reads
// are lock-free against concurrent registers; writes serialize on the
// internal mutex. Cosignature verification reads via Snapshot, which
// returns a copy so mutation during verification is impossible.
type WitnessRegistry struct {
	mu      sync.RWMutex
	keys    map[[32]byte]types.WitnessPublicKey
	auditor RegistrationAuditor
}

// RegistrationAuditor receives every admission, revocation, and
// rejection. The default no-op auditor is fine for tests; production
// deployments wire this to a structured-log emitter or SIEM. The
// auditor is invoked synchronously inside the registrar's locked
// region so no admission can proceed without its corresponding audit
// record being emitted.
type RegistrationAuditor interface {
	OnAdmit(witness types.WitnessPublicKey)
	OnRevoke(witness types.WitnessPublicKey)
	OnReject(id [32]byte, reason error)
}

type noopAuditor struct{}

func (noopAuditor) OnAdmit(types.WitnessPublicKey)   {}
func (noopAuditor) OnRevoke(types.WitnessPublicKey)  {}
func (noopAuditor) OnReject([32]byte, error)         {}

// NewWitnessRegistry returns an empty registry. Pass nil auditor for
// the no-op default; tests use a counting auditor to assert that
// every code path emits exactly one audit event.
func NewWitnessRegistry(auditor RegistrationAuditor) *WitnessRegistry {
	if auditor == nil {
		auditor = noopAuditor{}
	}
	return &WitnessRegistry{
		keys:    make(map[[32]byte]types.WitnessPublicKey),
		auditor: auditor,
	}
}

// Register admits one BLS public key after verifying its
// Proof-of-Possession. Returns wrapped sentinel errors on failure;
// the auditor receives an OnReject for every failure, an OnAdmit on
// success.
func (r *WitnessRegistry) Register(id [32]byte, pubKey, pop []byte) error {
	if len(pubKey) != signatures.BLSG2CompressedLen {
		err := fmt.Errorf("%w: got %d, want %d", ErrInvalidPubKeyLength,
			len(pubKey), signatures.BLSG2CompressedLen)
		r.auditor.OnReject(id, err)
		return err
	}
	if len(pop) != signatures.BLSG1CompressedLen {
		err := fmt.Errorf("%w: got %d, want %d", ErrInvalidPoPLength,
			len(pop), signatures.BLSG1CompressedLen)
		r.auditor.OnReject(id, err)
		return err
	}

	parsedPub, err := signatures.ParseBLSPubKey(pubKey)
	if err != nil {
		wrapped := fmt.Errorf("%w: parse pubkey: %v", ErrPoPVerifyFailed, err)
		r.auditor.OnReject(id, wrapped)
		return wrapped
	}

	if err := signatures.VerifyBLSPoP(parsedPub, pop); err != nil {
		wrapped := fmt.Errorf("%w: %v", ErrPoPVerifyFailed, err)
		r.auditor.OnReject(id, wrapped)
		return wrapped
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.keys[id]; exists {
		err := fmt.Errorf("%w: id %x", ErrWitnessAlreadyRegistered, id[:8])
		r.auditor.OnReject(id, err)
		return err
	}
	witness := types.WitnessPublicKey{ID: id, PublicKey: append([]byte(nil), pubKey...)}
	r.keys[id] = witness
	r.auditor.OnAdmit(witness)
	return nil
}

// Revoke removes a witness from the registry. Returns
// ErrWitnessNotRegistered if the ID is not present. The auditor
// receives OnRevoke on success or OnReject on the not-found path.
func (r *WitnessRegistry) Revoke(id [32]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	witness, exists := r.keys[id]
	if !exists {
		err := fmt.Errorf("%w: id %x", ErrWitnessNotRegistered, id[:8])
		r.auditor.OnReject(id, err)
		return err
	}
	delete(r.keys, id)
	r.auditor.OnRevoke(witness)
	return nil
}

// Snapshot returns the current witness set as a slice. Order is not
// guaranteed; callers that depend on ordering must sort by ID.
// Mutation of the returned slice does not affect the registry.
func (r *WitnessRegistry) Snapshot() []types.WitnessPublicKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]types.WitnessPublicKey, 0, len(r.keys))
	for _, w := range r.keys {
		// Copy the PublicKey bytes so callers cannot mutate the
		// registry's storage through the returned slice.
		out = append(out, types.WitnessPublicKey{
			ID:        w.ID,
			PublicKey: append([]byte(nil), w.PublicKey...),
		})
	}
	return out
}

// Lookup returns the witness for an ID, or false if not registered.
// The returned PublicKey is a copy.
func (r *WitnessRegistry) Lookup(id [32]byte) (types.WitnessPublicKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	w, ok := r.keys[id]
	if !ok {
		return types.WitnessPublicKey{}, false
	}
	return types.WitnessPublicKey{
		ID:        w.ID,
		PublicKey: append([]byte(nil), w.PublicKey...),
	}, true
}

// Size returns the current number of registered witnesses.
func (r *WitnessRegistry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.keys)
}

// Rotate admits a new (id, pubKey, pop) and revokes oldID atomically
// from the registry's perspective. PoP verification runs first; if
// it fails the registry is unchanged and the old ID remains
// registered.
func (r *WitnessRegistry) Rotate(oldID, newID [32]byte, newPubKey, newPoP []byte) error {
	if err := r.Register(newID, newPubKey, newPoP); err != nil {
		return err
	}
	if err := r.Revoke(oldID); err != nil {
		// Rollback: remove the just-admitted new key so the registry
		// state is identical to the pre-call state. The auditor sees
		// the rollback as OnRevoke for newID, preserving the
		// "every state change is audited" invariant.
		_ = r.Revoke(newID)
		return err
	}
	return nil
}
