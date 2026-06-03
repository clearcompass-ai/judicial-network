// Package bootstrap loads + interprets the shared trust root
// (network-bootstrap.json) for the scenarios that assert on it (S0.2, S0.4)
// and the cosign-verify path (S6.1, prerequisite H5).
package bootstrap

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	sdknetwork "github.com/clearcompass-ai/attesta/network"

	"github.com/clearcompass-ai/judicial-network/e2e/internal/types"
)

// Secp256k1DIDPrefix marks a did:key encoding a secp256k1 public key — the
// curve the ledger requires. The P-256 boot bug is exactly the negative of
// this (S0.4).
const Secp256k1DIDPrefix = "did:key:zQ3s"

// Load reads + parses network-bootstrap.json at path.
func Load(path string) (types.BootstrapDocument, error) {
	var d types.BootstrapDocument
	b, err := os.ReadFile(path)
	if err != nil {
		return d, fmt.Errorf("read bootstrap %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, fmt.Errorf("parse bootstrap %s: %w", path, err)
	}
	// Compute the cosign NetworkID via the SDK's OWN derivation (IDs() =
	// SHA-256 over the canonical bootstrap), so it equals what the
	// ledger/witnesses signed under. The e2e struct is lossy (e.g. no
	// genesis_admission_authorities), so the full-fidelity SDK document is the
	// only correct preimage. Best-effort: a malformed doc leaves NetworkID zero
	// and cosign verification fails closed.
	var nb sdknetwork.BootstrapDocument
	if json.Unmarshal(b, &nb) == nil {
		if ids, ierr := nb.IDs(); ierr == nil {
			d.NetworkID = [32]byte(ids.NetworkID)
		}
	}
	return d, nil
}

// IsSecp256k1 reports whether did is a secp256k1 did:key.
func IsSecp256k1(did string) bool {
	return strings.HasPrefix(did, Secp256k1DIDPrefix)
}
