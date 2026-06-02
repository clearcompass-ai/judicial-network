// FILE PATH: cmd/network-api/witness_bls_source.go
//
// BLS cross-log witness key-sourcing. A BLS-G2 witness cannot be a did:key
// (the multicodec carries no proof-of-possession slot), so witness.KeysFromDIDs
// — the resolver behind every WitnessDIDs row — can never yield its key
// material. The ONLY zero-trust source is the witness's on-log
// WitnessEndpointDeclaration (attesta v1.54: scheme/key/PoP), projected by
// crosslog.BLSWitnessesFromDeclarations for the AUTHORIZED PubKeyIDs.
//
// This file composes the existing primitives — it adds no new SDK surface:
//
//	snapshot file (envelope wire bytes)         loadWitnessDeclSnapshot
//	  → crosslog.MaterializeFromEntries         → MaterializedNetwork{Endpoints,…}
//	  → crosslog.RunAdvisoryCrossChecks         (advisory did:web drift, via the
//	                                             DID resolver — the "find the host"
//	                                             cross-check; non-fatal)
//	  → crosslog.BLSWitnessesFromDeclarations   → []crosslog.BLSWitness
//	  → WitnessSetSpec.BLSWitnesses             (folded in by the 3 build sites;
//	                                             PoP verified at NewWitnessKeySet)
//
// The declaration snapshot is the operator's view of the peer log's on-log
// declarations (the auditor produces it the same way as AUDITOR_REGISTRY_FILE).
// The live on-log walker is the drop-in replacement for the snapshot once it
// lands — the composition above is identical either way (it already runs on a
// MaterializedNetwork).
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/network"
	"github.com/clearcompass-ai/attesta/types"

	"github.com/clearcompass-ai/attesta-tools/libs/crosslog"
)

// witnessDeclSnapshotEntry is one on-log WitnessEndpointDeclaration entry in
// the operator-supplied snapshot: the canonical envelope wire bytes (base64)
// plus the log position they were observed at. This is exactly what a log scan
// / the future on-log walker yields per entry.
type witnessDeclSnapshotEntry struct {
	LogDID   string `json:"log_did"`
	Sequence uint64 `json:"sequence"`
	EntryB64 string `json:"entry_b64"`
}

// witnessSpecWithBLS builds the crosslog.WitnessSetSpec for one cross-log
// witness set, folding any BLS witnesses sourced from the log's declaration
// snapshot into BLSWitnesses alongside the ECDSA WitnessDIDs. With no snapshot
// configured it returns the prior ECDSA-only spec verbatim.
func witnessSpecWithBLS(
	logDID string,
	witnessDIDs []string,
	quorumK int,
	declFile string,
	authorizedIDsHex []string,
) (crosslog.WitnessSetSpec, error) {
	bls, err := sourceBLSWitnesses(logDID, declFile, authorizedIDsHex)
	if err != nil {
		return crosslog.WitnessSetSpec{}, err
	}
	return crosslog.WitnessSetSpec{
		LogDID:       logDID,
		WitnessDIDs:  witnessDIDs,
		BLSWitnesses: bls,
		QuorumK:      quorumK,
	}, nil
}

// sourceBLSWitnesses projects the authorized BLS witnesses for one log from its
// on-log WitnessEndpointDeclaration snapshot.
//
// declFile == "" ⇒ (nil, nil): the ECDSA-only default, byte-identical to prior
// behavior. Otherwise it loads + materializes the snapshot, runs the advisory
// did:web cross-check via the DID resolver (best-effort; non-fatal), and
// projects the key material for the AUTHORIZED PubKeyIDs at the latest snapshot
// position. cosign.NewWitnessKeySet (in BuildWitnessSetsForPolicy) verifies
// every returned PoP at set construction.
func sourceBLSWitnesses(logDID, declFile string, authorizedIDsHex []string) ([]crosslog.BLSWitness, error) {
	if declFile == "" {
		return nil, nil
	}
	logger := slog.Default()

	entries, err := loadWitnessDeclSnapshot(declFile)
	if err != nil {
		return nil, fmt.Errorf("witness declarations %q: %w", declFile, err)
	}
	materialized := crosslog.MaterializeFromEntries(entries, logger)

	// Advisory did:web cross-check: a domain-level compromise of a witness's
	// did:web origin surfaces here as on-log vs did:web drift WITHOUT changing
	// what the resolver returns (the on-log surface stays authoritative). The
	// DID resolver is the "find the host name" seam. Best-effort + non-fatal:
	// a resolver-build failure or a transient did:web fetch never blocks
	// sourcing.
	if resolver, derr := buildDIDResolver(); derr == nil && resolver != nil {
		if mismatches := crosslog.RunAdvisoryCrossChecks(context.Background(), materialized, resolver, logger); len(mismatches) > 0 {
			logger.Warn("witness_bls_source: did:web cross-check drift detected",
				"log_did", logDID, "mismatches", len(mismatches))
		}
	} else if derr != nil {
		logger.Debug("witness_bls_source: DID resolver unavailable; skipping advisory did:web cross-check",
			"log_did", logDID, "err", derr)
	}

	authorizedIDs, err := parseWitnessPubKeyIDs(authorizedIDsHex)
	if err != nil {
		return nil, fmt.Errorf("witness set %q: %w", logDID, err)
	}

	asOf := types.LogPosition{LogDID: logDID, Sequence: latestSequence(materialized.Endpoints, logDID)}
	bls, err := crosslog.BLSWitnessesFromDeclarations(materialized.Endpoints, authorizedIDs, asOf)
	if err != nil {
		return nil, fmt.Errorf("witness set %q: project BLS witnesses: %w", logDID, err)
	}
	return bls, nil
}

// loadWitnessDeclSnapshot reads the JSON snapshot and deserializes each entry's
// canonical wire bytes into the positioned form MaterializeFromEntries consumes.
func loadWitnessDeclSnapshot(path string) ([]crosslog.EntryAtPosition, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rows []witnessDeclSnapshotEntry
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("parse snapshot JSON: %w", err)
	}
	out := make([]crosslog.EntryAtPosition, 0, len(rows))
	for i, r := range rows {
		if r.LogDID == "" {
			return nil, fmt.Errorf("entry[%d]: log_did required", i)
		}
		wire, err := base64.StdEncoding.DecodeString(r.EntryB64)
		if err != nil {
			return nil, fmt.Errorf("entry[%d] (seq %d): base64 decode: %w", i, r.Sequence, err)
		}
		e, err := envelope.Deserialize(wire)
		if err != nil {
			return nil, fmt.Errorf("entry[%d] (seq %d): deserialize: %w", i, r.Sequence, err)
		}
		out = append(out, crosslog.EntryAtPosition{
			Position: types.LogPosition{LogDID: r.LogDID, Sequence: r.Sequence},
			Entry:    e,
		})
	}
	return out, nil
}

// parseWitnessPubKeyIDs decodes hex-encoded 32-byte witness PubKeyIDs (the
// authorized-set membership authority).
func parseWitnessPubKeyIDs(hexIDs []string) ([][32]byte, error) {
	out := make([][32]byte, 0, len(hexIDs))
	for i, h := range hexIDs {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("authorized_bls_witness_ids[%d]: not hex: %w", i, err)
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("authorized_bls_witness_ids[%d]: want 32 bytes, got %d", i, len(b))
		}
		var id [32]byte
		copy(id[:], b)
		out = append(out, id)
	}
	return out, nil
}

// latestSequence returns the highest declaration position observed for logDID —
// the "current" as-of at which key material is resolved (most recent
// non-retired declaration wins; a witness retired at/before this position is
// not projected).
func latestSequence(records network.WitnessEndpointDeclarationByPosition, logDID string) uint64 {
	var max uint64
	for _, rec := range records {
		if rec.EffectivePos.LogDID == logDID && rec.EffectivePos.Sequence > max {
			max = rec.EffectivePos.Sequence
		}
	}
	return max
}
