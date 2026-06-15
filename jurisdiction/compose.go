/*
FILE PATH: jurisdiction/compose.go

DESCRIPTION:

	Compose — the AUTHORING direction of a Bundle. It reads the SAME policies the
	SubmitGate validates against and EMITS a baseproof-entry-spec/v1 (the bridge
	artifact baseproof-cli's `submit --spec` executes):

	  template  := b.EntryTemplates().Lookup(event)   shape + primary (authority inversion)
	  rule      := b.CosignaturePolicy().Lookup(event) cosigner roles, K, filer, credentials
	  prereq      b.PrerequisitePolicy() walk           fail BEFORE composing (authoring-time)
	  weave       filed_by_capacity / signed_by_capacities from the rule + cast (real DIDs)
	  resolve     roles → key files via the cast         (keys never enter the Bundle)
	  emit        *entryspec.EntrySpec

	One source of truth, two directions: an authored entry structurally cannot
	drift from what the gate accepts. Keys live in the cast (per-run input), never
	in the Bundle — the emitted spec carries key-FILE paths, never secrets.

	Scope: today Compose authors ORIGIN entries (a case root such as
	case_initiation) — what EntrySpec's same-signer authority expresses. Dependent
	events (Path-A amendments, Path-B delegated entries) additionally need the
	case-root context the v0.7.0 scanner provides + amendment/delegation fields on
	the spec; the prerequisite walk here already refuses to author them until that
	context is supplied (a populated CaseContext), which is the same EvalContext
	the gate will consume.
*/
package jurisdiction

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/baseproof/tooling/libs/entryspec"
	prerequisites "github.com/baseproof/tooling/libs/prereq"

	"github.com/clearcompass-ai/judicial-network/schemas"
)

// CastMember binds a role to a concrete identity for one run. The Bundle speaks
// roles; the cast supplies the keys + DIDs (deployment/scenario config that
// lives in neither policy layer).
type CastMember struct {
	// Role is the catalog Signer role (court_clerk, judge, ...) for a
	// primary/cosigner, or the FilerRole (civil_attorney, ...) for a filer.
	Role string
	// DID is the member's signing DID; for a filer it must equal
	// filed_by_capacity.did and appear in the entry's Signatures.
	DID string
	// KeyFile is the path to this member's KeyFile JSON (entryspec format).
	KeyFile string
	// Exchange is the institutional DID this Signer belongs to
	// (signed_by_capacities.exchange). Defaults to the bundle's ExchangeDID.
	Exchange string
	// DelegationRef is the cosigner's most-recent delegation entry. Optional
	// in trust-mode verification; required by the verifying-mode resolver.
	DelegationRef *schemas.LogPositionRef
	// Credentials is the filer's credential map (e.g. {"bpr_number": "..."}).
	Credentials map[string]string
}

// Cast names the identities playing each role in one composed entry.
type Cast struct {
	// Primary signs first (Signatures[0]); its Role must equal the
	// template's PrimaryRole.
	Primary CastMember
	// Filer is the filing party (attorney) for filer events — woven into
	// filed_by_capacity AND added as a signature. nil for signer-only events.
	Filer *CastMember
	// Cosigners are the signer-of-record cosignatures (clerks, judges) that
	// satisfy the cosignature rule's RequiredSignerRoles / MinSignerCosigners.
	Cosigners []CastMember
}

// Values are the caller-supplied field values (docket, caption, disposition…)
// the template's Skeleton consumes. Scenario input, not Bundle knowledge.
type Values map[string]any

// CaseContext is the case state both directions share: Compose reads it to
// author references + pass the prerequisite walk; the SubmitGate's walker reads
// the same shape to validate. Empty (or nil) ⇒ an origin event with no
// ancestors — the only thing composable until the case-root scanner lands.
type CaseContext struct {
	RootRef                string
	ObservedEvents         []string
	PrimaryAuthorityScopes []string
}

func (cc *CaseContext) evalContext() prerequisites.EvalContext {
	if cc == nil {
		return prerequisites.EvalContext{}
	}
	return prerequisites.EvalContext{
		RootRef:                cc.RootRef,
		ObservedEvents:         cc.ObservedEvents,
		PrimaryAuthorityScopes: cc.PrimaryAuthorityScopes,
	}
}

// Compose authors one entry as a spec, derived entirely from the Bundle's
// policies + the cast. It fails BEFORE emitting if the prerequisite walk
// rejects the event in the given context, or if the cast cannot satisfy the
// cosignature rule.
func Compose(b Bundle, event string, cast Cast, cc *CaseContext, v Values) (*entryspec.EntrySpec, error) {
	tp, ok := b.(TemplateProvider)
	if !ok {
		return nil, fmt.Errorf("compose: bundle %s exposes no entry templates", b.ExchangeDID())
	}
	tmpl, ok := tp.EntryTemplates().Lookup(event)
	if !ok {
		return nil, fmt.Errorf("compose: no template for event %q in %s", event, b.ExchangeDID())
	}
	if cast.Primary.Role != tmpl.PrimaryRole {
		return nil, fmt.Errorf("compose %s: primary role %q does not match template PrimaryRole %q",
			event, cast.Primary.Role, tmpl.PrimaryRole)
	}
	if cast.Primary.KeyFile == "" || cast.Primary.DID == "" {
		return nil, fmt.Errorf("compose %s: primary cast member needs DID + KeyFile", event)
	}

	// Cosignature rule (some events are single-signer with no rule).
	rule, lerr := b.CosignaturePolicy().Lookup(event)
	if lerr != nil {
		rule = nil
	}

	// Authoring-time prerequisite walk — refuse to author what the gate would
	// reject. For origin events with an empty context this passes; dependent
	// events require a populated CaseContext.
	walker := &prerequisites.Walker{Policy: b.PrerequisitePolicy()}
	if verdict := walker.Check(event, cc.evalContext()); !verdict.OK {
		return nil, fmt.Errorf("compose %s: prerequisite gate (%s): %s", event, verdict.Rejection, verdict.Reason)
	}

	// Cast must satisfy the rule.
	if rule != nil {
		if len(rule.AllowedFilerRoles) > 0 && cast.Filer == nil {
			return nil, fmt.Errorf("compose %s: event requires a filer (allowed: %v)", event, rule.AllowedFilerRoles)
		}
		min := rule.MinSignerCosigners
		if min == 0 {
			min = 1
		}
		if len(cast.Cosigners) < min {
			return nil, fmt.Errorf("compose %s: rule needs ≥%d cosigner(s) of %v, cast has %d",
				event, min, rule.RequiredSignerRoles, len(cast.Cosigners))
		}
	}

	// Payload skeleton (domain fields + enums), then weave the capacity blocks.
	payload, err := tmpl.Skeleton(cc, v)
	if err != nil {
		return nil, fmt.Errorf("compose %s: skeleton: %w", event, err)
	}
	if payload == nil {
		payload = map[string]any{}
	}
	payload["event_type"] = event

	if cast.Filer != nil {
		for _, cred := range rule.RequiredCredentials {
			if cast.Filer.Credentials[cred] == "" {
				return nil, fmt.Errorf("compose %s: filer missing required credential %q", event, cred)
			}
		}
		payload["filed_by_capacity"] = schemas.FiledByCapacity{
			Actor:       schemas.ActorFiler,
			Role:        schemas.FilerRole(cast.Filer.Role),
			DID:         cast.Filer.DID,
			Credentials: cast.Filer.Credentials,
			SwornAt:     time.Now().UTC().Format(time.RFC3339Nano),
		}
	}

	if len(cast.Cosigners) > 0 {
		sbc := make([]schemas.SignedByCapacity, 0, len(cast.Cosigners))
		for _, c := range cast.Cosigners {
			ex := c.Exchange
			if ex == "" {
				ex = b.ExchangeDID()
			}
			sbc = append(sbc, schemas.SignedByCapacity{
				DID:           c.DID,
				Role:          c.Role,
				Exchange:      ex,
				DelegationRef: c.DelegationRef,
			})
		}
		payload["signed_by_capacities"] = sbc
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("compose %s: marshal payload: %w", event, err)
	}

	// Resolve roles → key files. Cosigner signatures: the signer-of-record
	// cosigners, plus the filer (its DID must appear in Signatures).
	cosignerKeys := make([]string, 0, len(cast.Cosigners)+1)
	for _, c := range cast.Cosigners {
		cosignerKeys = append(cosignerKeys, c.KeyFile)
	}
	if cast.Filer != nil {
		cosignerKeys = append(cosignerKeys, cast.Filer.KeyFile)
	}

	return &entryspec.EntrySpec{
		Format:           entryspec.Format,
		Schema:           tmpl.SchemaURI,
		Destination:      b.ExchangeDID(),
		PrimarySignerKey: cast.Primary.KeyFile,
		CosignerKeys:     cosignerKeys,
		Payload:          raw,
	}, nil
}
