// FILE PATH: cmd/network-api/witness_bls_source.go
//
// BLS cross-log witness key-sourcing — thin config glue over the shared,
// domain-agnostic crosslog builders. A BLS-G2 witness cannot be a did:key (the
// multicodec carries no proof-of-possession slot), so witness.KeysFromDIDs — the
// resolver behind every WitnessDIDs row — can never yield its key material; the
// only zero-trust source is the witness's on-log WitnessEndpointDeclaration
// (scheme/key/PoP, baseproof v1.54).
//
// The materialize/validate/project walkers are domain-agnostic and used by every
// network's auditor, so they live in attesta-tools/libs/crosslog (the witness
// twin of AuditorSpec / BuildAuditorRegistryFromConfig). This file only decodes
// JN's config rows and calls them:
//
//	declaration file (operator JSON, hex key material)
//	  -> loadWitnessEndpointSpecs                    -> []crosslog.WitnessEndpointSpec
//	  -> crosslog.BuildWitnessEndpointsFromConfig    -> WitnessEndpointDeclarationByPosition
//	  -> crosslog.BLSWitnessesFromDeclarationsLatest -> []crosslog.BLSWitness
//	  -> WitnessSetSpec.BLSWitnesses                 (PoP verified at NewWitnessKeySet)
//
// The declaration file is the operator's view of the log's on-log endpoint
// declarations (produced like AUDITOR_REGISTRY_FILE). The live on-log walker
// (crosslog.MaterializeFromEntries over a log scan) is the drop-in that yields
// the same WitnessEndpointDeclarationByPosition once declarations are on-log —
// both feed the same projection, so this path is unchanged when it lands. The
// did:web drift cross-check (crosslog.RunAdvisoryCrossChecks) belongs to that
// live-walker path: it cross-checks UNTRUSTED on-log declarations against the
// witness's did:web document, which is moot for operator-supplied config rows.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/clearcompass-ai/attesta-tools/libs/crosslog"
)

// witnessEndpointDeclJSON is the JSON/hex wire shape of one on-log witness
// endpoint declaration in the operator's declaration file — the witness twin of
// the auditor's AuditorSpec manifest row. Bytes are hex (JSON cannot carry raw
// bytes); the loader decodes them into crosslog.WitnessEndpointSpec.
type witnessEndpointDeclJSON struct {
	EffectiveSeq      uint64            `json:"effective_seq"`
	PubKeyID          string            `json:"pub_key_id"` // hex, 32 bytes
	Endpoints         map[string]string `json:"endpoints"`
	SchemeTag         uint8             `json:"scheme_tag"`                    // 1=ECDSA, 2=BLS
	PublicKey         string            `json:"public_key,omitempty"`          // hex (96 for BLS; empty for ECDSA)
	ProofOfPossession string            `json:"proof_of_possession,omitempty"` // hex (48 for BLS; empty for ECDSA)
	RetiredAt         *uint64           `json:"retired_at,omitempty"`
}

// witnessSpecWithBLS builds the crosslog.WitnessSetSpec for one cross-log
// witness set, folding any BLS witnesses sourced from the log's declaration file
// into BLSWitnesses alongside the ECDSA WitnessDIDs. With no file configured it
// returns the prior ECDSA-only spec verbatim.
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
// on-log WitnessEndpointDeclaration file.
//
// declFile == "" → (nil, nil): the ECDSA-only default, byte-identical to prior
// behavior. Otherwise it decodes the declaration specs, builds the SDK record
// slice via the shared crosslog.BuildWitnessEndpointsFromConfig (which validates
// the v1.54 scheme/key/PoP contract, incl. SHA-256(PublicKey)==PubKeyID, per
// row), and projects the key material for the AUTHORIZED PubKeyIDs at the latest
// position via crosslog.BLSWitnessesFromDeclarationsLatest. The membership
// authority (authorizedIDsHex) is NOT self-asserted from the declarations.
func sourceBLSWitnesses(logDID, declFile string, authorizedIDsHex []string) ([]crosslog.BLSWitness, error) {
	if declFile == "" {
		return nil, nil
	}
	specs, err := loadWitnessEndpointSpecs(declFile)
	if err != nil {
		return nil, fmt.Errorf("witness declarations %q: %w", declFile, err)
	}
	records, err := crosslog.BuildWitnessEndpointsFromConfig(specs)
	if err != nil {
		return nil, fmt.Errorf("witness set %q: %w", logDID, err)
	}
	authorizedIDs, err := parseWitnessPubKeyIDs(authorizedIDsHex)
	if err != nil {
		return nil, fmt.Errorf("witness set %q: %w", logDID, err)
	}
	bls, err := crosslog.BLSWitnessesFromDeclarationsLatest(records, authorizedIDs)
	if err != nil {
		return nil, fmt.Errorf("witness set %q: project BLS witnesses: %w", logDID, err)
	}
	return bls, nil
}

// loadWitnessEndpointSpecs reads + decodes the operator's declaration file into
// the shared crosslog.WitnessEndpointSpec rows.
func loadWitnessEndpointSpecs(path string) ([]crosslog.WitnessEndpointSpec, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rows []witnessEndpointDeclJSON
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("parse declaration JSON: %w", err)
	}
	out := make([]crosslog.WitnessEndpointSpec, 0, len(rows))
	for i, r := range rows {
		id, err := decodeHex32(r.PubKeyID)
		if err != nil {
			return nil, fmt.Errorf("declarations[%d]: pub_key_id: %w", i, err)
		}
		var pub, pop []byte
		if r.PublicKey != "" {
			if pub, err = hex.DecodeString(r.PublicKey); err != nil {
				return nil, fmt.Errorf("declarations[%d]: public_key: %w", i, err)
			}
		}
		if r.ProofOfPossession != "" {
			if pop, err = hex.DecodeString(r.ProofOfPossession); err != nil {
				return nil, fmt.Errorf("declarations[%d]: proof_of_possession: %w", i, err)
			}
		}
		out = append(out, crosslog.WitnessEndpointSpec{
			EffectiveSeq:      r.EffectiveSeq,
			PubKeyID:          id,
			Endpoints:         r.Endpoints,
			SchemeTag:         r.SchemeTag,
			PublicKey:         pub,
			ProofOfPossession: pop,
			RetiredAt:         r.RetiredAt,
		})
	}
	return out, nil
}

// parseWitnessPubKeyIDs decodes hex-encoded 32-byte witness PubKeyIDs (the
// authorized-set membership authority).
func parseWitnessPubKeyIDs(hexIDs []string) ([][32]byte, error) {
	out := make([][32]byte, 0, len(hexIDs))
	for i, h := range hexIDs {
		id, err := decodeHex32(h)
		if err != nil {
			return nil, fmt.Errorf("authorized_bls_witness_ids[%d]: %w", i, err)
		}
		out = append(out, id)
	}
	return out, nil
}

// decodeHex32 decodes a hex string into a [32]byte, rejecting a wrong length.
func decodeHex32(h string) ([32]byte, error) {
	var id [32]byte
	b, err := hex.DecodeString(h)
	if err != nil {
		return id, fmt.Errorf("not hex: %w", err)
	}
	if len(b) != 32 {
		return id, fmt.Errorf("want 32 bytes, got %d", len(b))
	}
	copy(id[:], b)
	return id, nil
}
