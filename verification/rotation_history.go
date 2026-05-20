/*
FILE PATH: verification/rotation_history.go

DESCRIPTION:

	RotationHistorySource materializes the AUTHORITY-VERIFIED key-rotation
	history for a signer DID from its sequenced on-log rotation entries —
	the []verifier.RotationRecord that feeds verifier.VerifyKeyAtPosition
	(via AuthorityResolver.VerifyKeyAtPosition).

	# THE LEDGER/CONSUMER SPLIT

	An entry-signer rotation is a sequenced on-log entry whose DomainPayload
	is the canonical verifier.RotationPayload wire (entry_signer_rotation_v1,
	attesta v1.13.0). The ledger sequences it and STRUCTURALLY validates the
	payload at admission, but explicitly delegates AUTHORITY to the consumer
	(see ledger admission/rotation_entry_verifier.go). This type is that
	consumer: it proves the chain of custody.

	# AUTHORITY = THE CHAIN OF CUSTODY (old-key-signs)

	A rotation is authorized by the key it RETIRES — the originator's last
	act with the old key is to name its successor (the same model as the
	SDK's gossip originator rotation). So each rotation entry MUST carry a
	valid secp256k1 signature by the key active just before the entry's
	INTRINSIC sequenced position:

	  - the FIRST rotation is signed by initialKey (the DID's key before any
	    rotation, resolved by the caller from the root-entity profile);
	  - every later rotation is signed by the prior rotation's NewPublicKey.

	A rotation not so authorized breaks the chain, and Build rejects the
	WHOLE history (fail closed). Silently dropping a forged mid-chain
	rotation would shift every later key-at-position answer.

	# POSITION IS INTRINSIC

	EffectivePos comes from the entry's sequenced LogPosition (EntryWithMetadata.
	Position), never from the payload — a payload that named its own position
	could disagree with where the ledger actually sequenced it.

KEY DEPENDENCIES:
  - attesta/verifier: RotationPayload codec, RotationRecord, VerifyKeyAtPosition.
  - attesta/core/envelope: Deserialize, SigningPayload, EntryIdentity, SigAlgoECDSA.
  - attesta/crypto/signatures: ParsePubKey, VerifyEntry (secp256k1 forward-verify).
*/
package verification

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	"github.com/clearcompass-ai/attesta/types"
	"github.com/clearcompass-ai/attesta/verifier"
)

// SignerEntryQuerier enumerates a DID's on-log entries. Order is
// irrelevant — RotationHistorySource sorts by intrinsic position. Matches
// the existing JN QueryBySignerDID adapters (api/judicial/parties_query.go,
// cases.go), so production wiring is a one-line adapter.
type SignerEntryQuerier interface {
	QueryBySignerDID(ctx context.Context, signerDID string) ([]types.EntryWithMetadata, error)
}

var (
	// ErrNoInitialKey is returned when a DID has rotation entries but the
	// caller supplied no initial key to root the authority chain.
	ErrNoInitialKey = errors.New("verification/rotation_history: rotations present but initial key is empty")

	// ErrRotationChainBroken is returned when a rotation entry is not
	// signed by the key active just before its position — the chain of
	// custody is broken, so the whole history is rejected.
	ErrRotationChainBroken = errors.New("verification/rotation_history: rotation not authorized by the prior active key")

	// ErrRotationMalformed is returned when an entry declares the rotation
	// kind but its payload does not decode (should have been rejected at
	// ledger admission; treated as hard error here, not silently dropped).
	ErrRotationMalformed = errors.New("verification/rotation_history: malformed rotation entry")
)

// RotationHistorySource builds authority-verified rotation histories.
// Construct once with a Querier; safe for concurrent Build calls (it
// holds no mutable state).
type RotationHistorySource struct {
	Querier SignerEntryQuerier
}

// Build returns signerDID's authority-verified rotation history, sorted by
// EffectivePos ascending — ready to pass to verifier.VerifyKeyAtPosition.
//
// initialKey is the DID's secp256k1 public key before any rotation (the
// caller resolves it from the root-entity profile); it roots the authority
// chain. A DID with no rotation entries yields an empty slice and no error
// (VerifyKeyAtPosition then resolves to the caller's InitialKey).
//
// FAIL CLOSED: any rotation whose signature does not verify against the
// prior active key returns ErrRotationChainBroken and no records.
func (s *RotationHistorySource) Build(
	ctx context.Context,
	signerDID string,
	initialKey []byte,
) ([]verifier.RotationRecord, error) {
	metas, err := s.Querier.QueryBySignerDID(ctx, signerDID)
	if err != nil {
		return nil, fmt.Errorf("verification/rotation_history: query %q: %w", signerDID, err)
	}

	// Pair each rotation record with its source entry — the entry is
	// needed for the authority-chain signature check.
	type rotationPair struct {
		rec   verifier.RotationRecord
		entry *envelope.Entry
	}
	pairs := make([]rotationPair, 0, len(metas))

	for i := range metas {
		m := metas[i]
		entry, derr := envelope.Deserialize(m.CanonicalBytes)
		if derr != nil {
			return nil, fmt.Errorf("verification/rotation_history: deserialize entry at seq %d: %w",
				m.Position.Sequence, derr)
		}

		// Probe the kind discriminator first (mirrors the ledger's
		// admission gate): a non-JSON or non-rotation payload is simply
		// not a rotation entry — skip it. Only payloads that DECLARE the
		// rotation kind are held to the codec.
		var probe struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(entry.DomainPayload, &probe) != nil || probe.Kind != verifier.RotationPayloadKindV1 {
			continue
		}
		payload, perr := verifier.DecodeRotationPayload(entry.DomainPayload)
		if perr != nil {
			return nil, fmt.Errorf("%w at seq %d: %v", ErrRotationMalformed, m.Position.Sequence, perr)
		}
		identity, ierr := envelope.EntryIdentity(entry)
		if ierr != nil {
			return nil, fmt.Errorf("verification/rotation_history: entry identity at seq %d: %w",
				m.Position.Sequence, ierr)
		}
		pairs = append(pairs, rotationPair{
			rec:   payload.ToRecord(m.Position, identity),
			entry: entry,
		})
	}

	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].rec.EffectivePos.Less(pairs[j].rec.EffectivePos)
	})

	if len(pairs) > 0 && len(initialKey) == 0 {
		return nil, ErrNoInitialKey
	}

	// Walk in position order, verifying the chain of custody. active is
	// the key authoritative just before the current rotation's position.
	active := initialKey
	out := make([]verifier.RotationRecord, 0, len(pairs))
	for _, p := range pairs {
		if verr := verifyEntrySignedBy(p.entry, active); verr != nil {
			return nil, fmt.Errorf("%w: signer=%q seq=%d: %v",
				ErrRotationChainBroken, signerDID, p.rec.EffectivePos.Sequence, verr)
		}
		out = append(out, p.rec)
		active = p.rec.NewPublicKey
	}
	return out, nil
}

// verifyEntrySignedBy confirms entry.Signatures[0] is a valid secp256k1
// ECDSA signature over the entry by the key whose bytes are activeKey.
// The signed digest is sha256(SigningPayload(entry)) — the SDK's entry
// signing convention.
func verifyEntrySignedBy(entry *envelope.Entry, activeKey []byte) error {
	if len(entry.Signatures) == 0 {
		return errors.New("entry carries no signature")
	}
	sig := entry.Signatures[0]
	if sig.AlgoID != envelope.SigAlgoECDSA {
		return fmt.Errorf("signature AlgoID %d is not SigAlgoECDSA (entry-signer rotations are secp256k1)", sig.AlgoID)
	}
	pub, err := signatures.ParsePubKey(activeKey)
	if err != nil {
		return fmt.Errorf("parse active key: %w", err)
	}
	digest := sha256.Sum256(envelope.SigningPayload(entry))
	return signatures.VerifyEntry(digest, sig.Bytes, pub)
}
