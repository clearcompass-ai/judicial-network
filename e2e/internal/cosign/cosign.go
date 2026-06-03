// Package cosign is the consumer-side cosignature verifier used by the H5
// scenarios (S6.1, S7.1, S7.2): it recomputes a cosigned head's K-of-N witness
// signatures against the bootstrap's genesis set using the REAL baseproof SDK
// (crypto/cosign + witness.KeysFromDIDs), so those scenarios verify the math
// instead of trusting the publisher's JSON.
//
// The NetworkID the witnesses signed under is SHA-256(canonical bootstrap)
// (baseproof/network.BootstrapDocument.CanonicalBytes); internal/bootstrap.Load
// computes it via the SDK's own canonicalization and stores it on the document,
// so it matches by construction — see internal/bootstrap.
package cosign

import (
	"encoding/hex"
	"errors"
	"fmt"

	sdkcosign "github.com/baseproof/baseproof/crypto/cosign"
	baseprooftypes "github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	"github.com/clearcompass-ai/judicial-network/e2e/internal/types"
)

// ErrNotWired was returned by the stub before H5. Retained so Wired() and any
// caller that matched it keep compiling; the real Verify never returns it.
var ErrNotWired = errors.New("cosign verifier not wired")

// Result is the outcome of verifying a cosigned head against a witness set.
type Result struct {
	ValidCount int // signatures that verified under the genesis set
	Total      int // signatures presented
}

// Verify checks head's K-of-N cosignatures against the bootstrap's genesis
// witness set, via the baseproof SDK. A var so a test can swap it.
var Verify = func(boot types.BootstrapDocument, quorumK int, head types.CosignedTreeHead) (Result, error) {
	total := len(head.Signatures)
	keys, err := witness.KeysFromDIDs(boot.GenesisWitnessSet)
	if err != nil {
		return Result{Total: total}, fmt.Errorf("cosign: witness keys from genesis DIDs: %w", err)
	}
	set, err := sdkcosign.NewWitnessKeySet(keys, sdkcosign.NetworkID(boot.NetworkID), quorumK, nil)
	if err != nil {
		return Result{Total: total}, fmt.Errorf("cosign: build witness key set (k=%d of %d): %w", quorumK, len(keys), err)
	}
	ah, err := toBaseproofHead(head)
	if err != nil {
		return Result{Total: total}, err
	}
	// VerifyTreeHeadCosignatures recomputes the canonical message
	// (purpose‖0x00‖networkID‖algo‖head) from set.NetworkID() and returns the
	// number of valid K-of-N signatures.
	return Result{ValidCount: sdkcosign.VerifyTreeHeadCosignatures(ah, set), Total: total}, nil
}

// Wired reports whether the real verifier is installed (H5). True now.
func Wired() bool {
	_, err := Verify(types.BootstrapDocument{}, 0, types.CosignedTreeHead{})
	return !errors.Is(err, ErrNotWired)
}

// toBaseproofHead maps the e2e wire head (hex-string fields) to the SDK type the
// verifier consumes.
func toBaseproofHead(h types.CosignedTreeHead) (baseprooftypes.CosignedTreeHead, error) {
	var th baseprooftypes.TreeHead
	th.TreeSize = h.TreeSize
	for _, f := range []struct {
		name string
		src  string
		dst  *[32]byte
	}{
		{"root_hash", h.RootHash, &th.RootHash},
		{"smt_root", h.SMTRoot, &th.SMTRoot},
		{"receipt_root", h.ReceiptRoot, &th.ReceiptRoot},
	} {
		if f.src == "" {
			continue // empty receipt_root ⇒ the zero hash the witnesses cosigned
		}
		b, err := hex.DecodeString(f.src)
		if err != nil || len(b) != 32 {
			return baseprooftypes.CosignedTreeHead{}, fmt.Errorf("cosign: %s not a 32-byte hex hash", f.name)
		}
		copy(f.dst[:], b)
	}
	sigs := make([]baseprooftypes.WitnessSignature, 0, len(h.Signatures))
	for i, s := range h.Signatures {
		id, err := hex.DecodeString(s.PubKeyID)
		if err != nil || len(id) != 32 {
			return baseprooftypes.CosignedTreeHead{}, fmt.Errorf("cosign: signature[%d] pub_key_id not a 32-byte hex id", i)
		}
		sb, err := hex.DecodeString(s.SigBytes)
		if err != nil {
			return baseprooftypes.CosignedTreeHead{}, fmt.Errorf("cosign: signature[%d] sig_bytes not hex", i)
		}
		var pid [32]byte
		copy(pid[:], id)
		sigs = append(sigs, baseprooftypes.WitnessSignature{PubKeyID: pid, SchemeTag: byte(s.SchemeTag), SigBytes: sb})
	}
	return baseprooftypes.CosignedTreeHead{TreeHead: th, Signatures: sigs}, nil
}
