/*
FILE PATH:

	verification/trust/burn.go

DESCRIPTION:

	StatusFor is the JN chokepoint that turns the gossip layer's
	observed burn state into the SDK's pinned, offline
	verifier.TrustStatus (SDK-4 / ZT-SCN-07). Every JN cross-log call
	site (anchor.VerifyCrossLog, verifier.VerifyCrossLogProof, the
	appeal-chain walker) feeds its source-log trust through here, so
	the SDK's trust.Gate is the single place burn state is enforced —
	JN owns DETECTION (the gossip reconciler writes the HeadsJournal),
	the SDK owns the GATE.

KEY ARCHITECTURAL DECISION:

	Fail-closed by construction. A successful journal read sets
	Known=true (we genuinely consulted a burn source); the gate then
	rejects only an actually-burned source (ErrEquivocatedLog). A nil
	journal (no burn source wired) or a read error yields the ZERO
	value (Known=false), which gates closed with ErrTrustUnknown. We
	never synthesise Known=true without a real consult — that would
	defeat SDK-4.
*/
package trust

import (
	"context"

	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"

	"github.com/clearcompass-ai/attesta-tools/libs/monitoring"
)

// StatusFor maps logDID's heads-journal burn status to a pinned,
// offline verifier.TrustStatus. See file header for the fail-closed
// contract. ctx bounds the (local, in-memory or DB) journal read.
func StatusFor(ctx context.Context, journal monitoring.HeadsJournal, logDID string) verifier.TrustStatus {
	if journal == nil {
		return verifier.TrustStatus{} // Known=false → Gate fails closed (ErrTrustUnknown)
	}
	bs, err := journal.BurnStatus(ctx, logDID)
	if err != nil {
		return verifier.TrustStatus{} // unconsulted → fail closed
	}
	return verifier.TrustStatus{
		Known:  true,
		Burned: bs.Burned,
		// AsOf is advisory/forensic (not consulted by Gate): record the
		// position the burn was first observed so a verdict can name the
		// burn snapshot it relied on.
		AsOf: types.LogPosition{LogDID: logDID, Sequence: bs.FirstForkSequence},
	}
}
