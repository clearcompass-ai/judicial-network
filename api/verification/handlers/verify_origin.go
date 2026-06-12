package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/smt"
	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/schema"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"

	"github.com/baseproof/tooling/libs/monitoring"

	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/verification/trust"

	"github.com/clearcompass-ai/judicial-network/verification/eras"
)

// Dependencies shared across all verification handlers.
// Uses real SDK interfaces — no invented abstractions.
//
// History: v0.3.0 collapsed the legacy trio into a per-log WitnessSets
// map; FED-1 #107 then replaced the map with the era resolver below.
// Original v0.3.0 note: WitnessSets replaced the legacy
// trio of WitnessKeys / WitnessQuorum / WitnessNetwork. SDK Principle
// 10 (Two-Tier Quorum Encapsulation): keys + K + NetworkID + BLS
// verifier are bound together at construction time inside one
// *cosign.WitnessKeySet — eliminating the class of bug where the
// three parallel maps drift out of sync for the same log DID.
type Dependencies struct {
	LogQueries     map[string]sdklog.LedgerQueryAPI
	LeafReader     smt.LeafReader
	Extractor      schema.SchemaParameterExtractor
	SchemaResolver builder.SchemaResolver

	// Journal is the verified-heads archive (shared with the gossip
	// reconciler). Two roles under baseproof v1.43.0:
	//   - SDK-4 cross-log trust: BurnStatus(sourceLogDID) → the pinned
	//     verifier.TrustStatus VerifyCrossLogHandler gates on (via
	//     trust.StatusFor).
	//   - ZT-IMM-01 historical pins: HeadAt(logDID, seq) supplies the
	//     RootHash for an explicit ?as_of=N selector (resolveAsOf).
	// nil fails both closed: cross-log → ErrTrustUnknown, explicit
	// ?as_of=N → error. The absent/latest path resolves via the trust
	// provider and is unaffected.
	Journal monitoring.HeadsJournal

	// MultiTrust is the C-3 cross-network LogTrustProvider. When
	// non-nil, the C-4 call sites in this package
	// (VerifyAuthorityHandler, VerifyBatchHandler) dispatch trust
	// through it — foreign-log positions resolve under their own
	// log's witness set and journaled head, home-log positions
	// resolve via the embedded LocalTrust. nil disables the
	// cross-network seam: PickTrust falls back to a freshly-
	// constructed LocalTrust over the per-request fetcher and the
	// (shared) LeafReader — byte-for-byte equivalent to the
	// pre-C-4 inline trust.NewLocalTrust(fetcher, deps.LeafReader)
	// each handler embedded directly.
	MultiTrust verifier.LogTrustProvider

	// Eras resolves the source log's witness set ERA-CORRECTLY for a
	// specific cosigned head (FED-1 #107): genesis trust root + the
	// journaled verified-rotation chain, era anchored by which chain
	// set's K-of-N the head's cosignatures satisfy. Replaces the static
	// per-log map (era-blind AND rotation-blind). Failures carry the
	// eras class sentinels (no-such-peer / warming / cannot-resolve-era).
	Eras eras.SetResolver

	// SignatureVerifier resolves DID method → SignatureVerifier for
	// the Path C admission gate (/v1/verify/complete). Production:
	// did.DefaultVerifierRegistry bound to the exchange's
	// destination DID with a configured PKHVerifierOptions (EOA-only
	// or full EIP-1271 K-of-N executor quorum). Per-handler
	// responsibility — only VerifyCompleteHandler reads this field.
	// Empty (nil) keeps boot clean for deployments that don't
	// expose /v1/verify/complete.
	SignatureVerifier attestation.SignatureVerifier

	// PR-2 (baseproof v1.5.1 / issue #75 read-time Stage 6).
	// PolicyStage holds per-log dependencies for the SDK Path C
	// composite's Policy stage. When the feature flag
	// JN_VERIFY_POLICY_STAGE_ENABLE is true AND PolicyStage has an
	// entry for the request's logID, VerifyCompleteHandler builds
	// verifier.PolicyStageParams via verification.BuildPolicyStageParams
	// and attaches it to the SDK call.
	//
	// Absent for any log (or feature flag off) keeps the three-stage
	// (Signatures + Authority + Origin) behavior the handler shipped
	// with in PR D. Both axes are independent: a wired log with the
	// flag off is silent; a flag-on log with no PolicyStage entry is
	// silent.
	PolicyStage map[string]PolicyStageDeps

	// PolicyStageEnabled gates the Policy stage. Read at boot from
	// JN_VERIFY_POLICY_STAGE_ENABLE. Default off until real
	// cosignature traffic exists to validate against.
	PolicyStageEnabled bool

	// LedgerHTTPClient is the boot-wired *http.Client used for
	// outbound HTTPS calls this handler set makes against an arbitrary
	// caller-named base URL — currently the Static-CT tile fetch in
	// VerifyConsistencyHandler. nil ⇒ a plain 15s client is used so
	// dev / pre-cert deployments behave as before. When the JN runs in
	// a peer-mTLS federation, this client carries the JN's client cert
	// so peer ledgers accept the connection.
	//
	// Wired in cmd/network-api/main.go (BuildLedgerSubmitClient over
	// cfg.Ledger{Cert,Key,CA}).
	LedgerHTTPClient *http.Client

	// Registry resolves an entry's destination bundle → cosignature policy +
	// exchange DID for the read-side crypto-aware cosignature check
	// (VerifyCosignatureHandler). The SAME registry the exchange submit gate
	// uses, so the read-side dual-verification applies the identical
	// per-jurisdiction rule table — only crypto-aware (CheckCosignatureWithVerifier
	// runs attestation.VerifyEntrySignatures first). nil ⇒ /v1/verify/cosignature
	// returns 503; only VerifyCosignatureHandler reads this field.
	Registry *jurisdiction.Registry
}

// PolicyStageDeps is the per-log injection point for read-time
// Stage 6 (baseproof v1.5.1). One per logID. Production wiring builds:
//
//   - Query:              *sdklog.HTTPLedgerQueryAPI (cosignature_of)
//   - Fetcher:            *sdklog.HTTPEntryFetcher (/raw bytes)
//   - DelegationResolver: *verification.LedgerDelegationResolver
//
// Tests inject fakes.
type PolicyStageDeps struct {
	Query              sdklog.LedgerQueryAPI
	Fetcher            types.EntryFetcher
	DelegationResolver attestation.DelegationResolver
}

// resolveLog finds the ledger query API for a given log identifier.
func (d *Dependencies) resolveLog(logID string) (sdklog.LedgerQueryAPI, bool) {
	q, ok := d.LogQueries[logID]
	return q, ok
}

// fetcherFor creates an EntryFetcher adapter for a specific log.
func (d *Dependencies) fetcherFor(logID string) (types.EntryFetcher, error) {
	query, ok := d.resolveLog(logID)
	if !ok {
		return nil, fmt.Errorf("unknown log %s", logID)
	}
	return &ledgerFetcher{query: query, logDID: logID}, nil
}

// PickTrust returns the LogTrustProvider the C-4 call sites in this
// package dispatch through. When MultiTrust is wired (cfg.
// GossipIngest.PeerLogs declared at boot), returns it — every
// foreign-log position resolves under its own log's witness set +
// journaled head. When MultiTrust is nil, falls back to a freshly-
// constructed LocalTrust over the per-request fetcher and the
// (shared) LeafReader — identical to the pre-C-4 inline
// trust.NewLocalTrust(fetcher, deps.LeafReader) shape every handler
// embedded directly.
//
// fetcher is the per-request, per-LogDID EntryFetcher built by
// fetcherFor — passing it here keeps the LocalTrust fallback path
// log-correct (the right LedgerQueryAPI threaded into Entry calls).
func (d *Dependencies) PickTrust(fetcher types.EntryFetcher) verifier.LogTrustProvider {
	if d.MultiTrust != nil {
		return d.MultiTrust
	}
	return trust.NewLocalTrust(fetcher, d.LeafReader)
}

// ledgerFetcher adapts LedgerQueryAPI to types.EntryFetcher.
// v0.3.0: Fetch now takes ctx so the underlying ScanFromPosition RPC
// honours the caller's request deadline.
type ledgerFetcher struct {
	query  sdklog.LedgerQueryAPI
	logDID string
}

func (f *ledgerFetcher) Fetch(ctx context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error) {
	entries, err := f.query.ScanFromPosition(ctx, pos.Sequence, 1)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("entry not found at %s", pos)
	}
	return &entries[0], nil
}

// VerifyOriginHandler handles GET /v1/verify/origin/{logID}/{pos}.
type VerifyOriginHandler struct{ deps *Dependencies }

func NewVerifyOriginHandler(deps *Dependencies) *VerifyOriginHandler {
	return &VerifyOriginHandler{deps: deps}
}

func (h *VerifyOriginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logID := r.PathValue("logID")
	posStr := r.PathValue("pos")

	pos, err := strconv.ParseUint(posStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid position")
		return
	}

	fetcher, err := h.deps.fetcherFor(logID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	leafKey := smt.DeriveKey(types.LogPosition{LogDID: logID, Sequence: pos})

	result, err := verifier.EvaluateOrigin(ctx, leafKey, h.deps.LeafReader, fetcher)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "origin evaluation failed")
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// ─── Shared helpers ──────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
