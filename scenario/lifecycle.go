package scenario

// The case lifecycle beyond initiation: the attorney filings and the judge's
// disposition that turn a bare case_initiation into a fully litigated case the
// verifier accepts.
//
// Per the tn/trial cosignature + prerequisite policy, a verifiable
// final_judgment REQUIRES a merits-posture ancestor (responsive_pleading /
// motion_*), and every merits-posture event is an ATTORNEY filing (a
// filed_by_capacity carrying a bpr_number). So the per-case lifecycle is:
//
//	case_initiation       clerk primary + clerk cosigner            (case_gen.go)
//	→ counsel_appearance   attorney filer + clerk cosign, BPR        (§1 genesis)
//	→ responsive_pleading  attorney filer + clerk cosign, BPR        (merits posture)
//	→ final_judgment       judge, single-signer, case_decision       (disposition)
//
// All are PAYLOAD-ONLY entries (no document artifact), so cases.File is called
// with nil artifact/schema/reader deps — those are dereferenced only when
// Plaintext is non-empty (cases/filing.go:87). The attorney filings ride Path A
// (same-signer amendment on the case root's primary clerk, so no delegation
// pointer is needed); final_judgment rides Path B (the judge's on-log
// delegation pointer, which the scope verifier walks for the case_decision
// grant). event_type / filed_by_capacity / signed_by_capacities are supplied
// via ExtraPayload — cases.File (unlike InitiateCase) sets none of them.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/tooling/libs/auth/identity"

	"github.com/clearcompass-ai/judicial-network/cases"
	"github.com/clearcompass-ai/judicial-network/delegation"
	"github.com/clearcompass-ai/judicial-network/schemas"
)

// toLogPosition converts a schemas.LogPositionRef (what the submit pipeline
// returns) to the SDK's types.LogPosition (what the cases builders consume).
// The two are field-identical; there is no implicit conversion.
func toLogPosition(ref schemas.LogPositionRef) types.LogPosition {
	return types.LogPosition{LogDID: ref.LogDID, Sequence: ref.Sequence}
}

// entryDisplay builds the EIP-712 typed-data display every signer's wallet
// renders. The Salt is the institutional DID so a signature cannot replay
// across courts. The provider requires a non-nil display with ≥1 field.
func entryDisplay(institutionalDID, primaryType string, fields ...identity.EIP712Field) *identity.TypedDataDisplay {
	return &identity.TypedDataDisplay{
		Domain:      identity.EIP712Domain{Name: "Judicial Network", Version: "v1", Salt: institutionalDID},
		PrimaryType: primaryType,
		Fields:      fields,
	}
}

// buildAttorneyFiling builds an UNSIGNED Path-A filing (counsel_appearance or
// responsive_pleading): the case's primary clerk is Signatures[0], the attorney
// files (filed_by_capacity + bpr_number), and a distinct second clerk cosigns
// of record. The cosignature mix counts only NON-primary cosigners, so the
// accepting clerk — not the primary — is what satisfies MinSignerCosigners.
//
// Submit via SignAndSubmitCosigned(..., cosigners=[attorney.DID, secondClerk.DID]):
// the attorney's signature is required because filed_by_capacity.did must appear
// in Signatures; the second clerk's is what the court_clerk threshold counts.
func buildAttorneyFiling(
	ctx context.Context,
	j Jurisdiction,
	caseRoot schemas.LogPositionRef,
	eventType, docType, docTitle, docket string,
	primaryClerk, secondClerk, attorney *Principal,
	when time.Time,
) (*envelope.Entry, error) {
	if attorney.FilerRole == "" || attorney.BPR == "" {
		return nil, fmt.Errorf("scenario: attorney %q missing filer role / bpr", attorney.Name)
	}
	if secondClerk.Delegation == nil {
		return nil, fmt.Errorf("scenario: cosigning clerk %q has no on-log delegation (seed first)", secondClerk.Name)
	}
	filer := schemas.FiledByCapacity{
		Actor:       schemas.ActorFiler,
		Role:        schemas.FilerRole(attorney.FilerRole),
		DID:         attorney.DID,
		Credentials: map[string]string{"bpr_number": attorney.BPR},
		SwornAt:     when.UTC().Format(time.RFC3339Nano),
	}
	clerkCap := schemas.SignedByCapacity{
		DID:           secondClerk.DID,
		Role:          secondClerk.Role, // court_clerk
		Exchange:      j.InstitutionalDID,
		DelegationRef: secondClerk.Delegation,
	}
	res, err := cases.File(ctx, cases.FilingConfig{
		Destination:   j.ExchangeDID,
		SignerDID:     primaryClerk.DID, // == case root signer ⇒ Path A (no delegation pointers)
		CaseRootPos:   toLogPosition(caseRoot),
		DocumentType:  docType,
		DocumentTitle: docTitle,
		EventTime:     when.UnixMicro(), // protocol time: micros, fresh (≈now) for the freshness gate
		ExtraPayload: map[string]interface{}{
			"event_type":           eventType,
			"docket_number":        docket,
			"filed_by_capacity":    filer,
			"signed_by_capacities": []schemas.SignedByCapacity{clerkCap},
		},
	}, nil, nil, nil, nil, nil, nil) // payload-only ⇒ no content/schema/reader deps touched
	if err != nil {
		return nil, fmt.Errorf("scenario: build %s %s: %w", eventType, docket, err)
	}
	return res.Entry, nil
}

// buildFinalJudgment builds an UNSIGNED signer-only final_judgment: the judge
// is the sole signer (Path B carrying the judge's on-log delegation pointer, so
// the scope verifier can walk it for the case_decision grant). NO
// filed_by_capacity / signed_by_capacities — a filer block would trip
// CosigRejectCapacityForbidden. Submit via signAndSubmitSingle.
func buildFinalJudgment(
	ctx context.Context,
	j Jurisdiction,
	caseRoot schemas.LogPositionRef,
	docket, disposition string,
	judge *Principal,
	when time.Time,
) (*envelope.Entry, error) {
	if judge.Delegation == nil {
		return nil, fmt.Errorf("scenario: judge %q has no on-log delegation (seed first)", judge.Name)
	}
	res, err := cases.File(ctx, cases.FilingConfig{
		Destination:        j.ExchangeDID,
		SignerDID:          judge.DID,
		CaseRootPos:        toLogPosition(caseRoot),
		DelegationPointers: []types.LogPosition{toLogPosition(*judge.Delegation)}, // ⇒ Path B
		DocumentType:       "final_judgment",
		DocumentTitle:      "Final Judgment",
		EventTime:          when.UnixMicro(), // protocol time: micros, fresh (≈now) for the freshness gate
		ExtraPayload: map[string]interface{}{
			"event_type":    "final_judgment",
			"docket_number": docket,
			"disposition":   disposition,
		},
	}, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("scenario: build final_judgment %s: %w", docket, err)
	}
	return res.Entry, nil
}

// signAndSubmitSingle drives the build→sign→submit pipeline for a single-signer
// entry (final_judgment), mirroring delegation's unexported signAndSubmit:
// every signer signs sha256(SigningPayload); the 65-byte SignCompact is trimmed
// to the 64-byte R||S the SDK's SigAlgoECDSA wants. delegation.SignAndSubmitCosigned
// rejects an empty cosigner list, so single-signer entries need this path.
func signAndSubmitSingle(
	ctx context.Context,
	bc *delegation.BuildContext,
	entry *envelope.Entry,
	display *identity.TypedDataDisplay,
	reason string,
) (schemas.LogPositionRef, error) {
	if bc == nil || bc.Identity == nil || bc.Submitter == nil {
		return schemas.LogPositionRef{}, errors.New("scenario: nil BuildContext / Identity / Submitter")
	}
	digest := sha256.Sum256(envelope.SigningPayload(entry))
	resp, err := bc.Identity.SignDigest(ctx, identity.SignRequest{
		SignerDID: entry.Header.SignerDID,
		Digest:    digest,
		Display:   display,
		Reason:    reason,
	})
	if err != nil {
		return schemas.LogPositionRef{}, fmt.Errorf("scenario: sign %s: %w", entry.Header.SignerDID, err)
	}
	if resp == nil || len(resp.Signature) == 0 {
		return schemas.LogPositionRef{}, fmt.Errorf("scenario: empty signature for %s", entry.Header.SignerDID)
	}
	sig := resp.Signature
	if len(sig) == 65 {
		sig = sig[1:] // strip recovery byte → 64-byte R||S
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: entry.Header.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	if err := entry.Validate(); err != nil {
		return schemas.LogPositionRef{}, fmt.Errorf("scenario: post-sign validate: %w", err)
	}
	canonical, err := envelope.Serialize(entry)
	if err != nil {
		return schemas.LogPositionRef{}, fmt.Errorf("scenario: serialize: %w", err)
	}
	return bc.Submitter.SubmitCanonical(ctx, canonical)
}
