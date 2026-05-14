package verification

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/attesta/core/envelope"
	"github.com/clearcompass-ai/attesta/crypto/signatures"
	sdklog "github.com/clearcompass-ai/attesta/log"
	"github.com/clearcompass-ai/attesta/types"
)

// signedPrimaryBytes builds a signed primary entry that optionally
// declares an AttestationPolicyName. Returns canonical bytes.
func signedPrimaryBytes(t *testing.T, signerDID string, policyName *string) []byte {
	t.Helper()
	auth := envelope.AuthoritySameSigner
	unsigned, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:             signerDID,
		Destination:           "did:web:dst",
		AuthorityPath:         &auth,
		AttestationPolicyName: policyName,
	}, []byte(`{"k":"v"}`))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	h := sha256.Sum256(envelope.SigningPayload(unsigned))
	sig, err := signatures.SignEntry(h, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	signed, err := envelope.NewEntry(unsigned.Header, unsigned.DomainPayload, []envelope.Signature{
		{SignerDID: signerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig},
	})
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	raw, err := envelope.Serialize(signed)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return raw
}

// fakeQuery implements just enough of sdklog.LedgerQueryAPI for the
// cosignature_of path; other methods return empty / error.
type fakeQuery struct {
	cosigsByTarget map[uint64][]types.EntryWithMetadata
	err            error
}

func (f *fakeQuery) QueryByCosignatureOf(_ context.Context, pos types.LogPosition) ([]types.EntryWithMetadata, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.cosigsByTarget[pos.Sequence], nil
}

func (f *fakeQuery) QueryByTargetRoot(_ context.Context, _ types.LogPosition) ([]types.EntryWithMetadata, error) {
	return nil, nil
}
func (f *fakeQuery) QueryBySignerDID(_ context.Context, _ string) ([]types.EntryWithMetadata, error) {
	return nil, nil
}
func (f *fakeQuery) QueryBySchemaRef(_ context.Context, _ types.LogPosition) ([]types.EntryWithMetadata, error) {
	return nil, nil
}
func (f *fakeQuery) ScanFromPosition(_ context.Context, _ uint64, _ int) ([]types.EntryWithMetadata, error) {
	return nil, nil
}

var _ sdklog.LedgerQueryAPI = (*fakeQuery)(nil)

func TestBuildPolicyStageParams_NoPolicyAdopted_ShortCircuit(t *testing.T) {
	primary := types.EntryWithMetadata{
		Position:       types.LogPosition{LogDID: "did:web:l", Sequence: 7},
		CanonicalBytes: signedPrimaryBytes(t, "did:web:p", nil),
		LogTime:        time.Unix(1, 0),
	}
	params, err := BuildPolicyStageParams(
		context.Background(),
		primary,
		&types.SchemaParameters{},
		&fakeQuery{},
		&delegFakeFetcher{},
		nil,
	)
	if err != nil {
		t.Fatalf("expected (nil, nil), got err %v", err)
	}
	if params != nil {
		t.Errorf("expected nil params for no-policy entry, got %+v", params)
	}
}

func TestBuildPolicyStageParams_PolicyAdopted_BuildsCandidates(t *testing.T) {
	name := "concurring_2"
	primary := types.EntryWithMetadata{
		Position:       types.LogPosition{LogDID: "did:web:l", Sequence: 42},
		CanonicalBytes: signedPrimaryBytes(t, "did:web:p", &name),
		LogTime:        time.Unix(1, 0),
	}
	schema := &types.SchemaParameters{
		AttestationPolicies: []types.AttestationPolicy{
			{Name: "concurring_2", MinAttestors: 2, Window: 24 * time.Hour},
		},
	}
	cosig1Bytes := signedPrimaryBytes(t, "did:web:c1", nil)
	cosig2Bytes := signedPrimaryBytes(t, "did:web:c2", nil)

	// Query returns candidates with CanonicalBytes==nil (matches the
	// SDK's HTTPLedgerQueryAPI egress mandate). The fetcher hydrates.
	q := &fakeQuery{cosigsByTarget: map[uint64][]types.EntryWithMetadata{
		42: {
			{Position: types.LogPosition{LogDID: "did:web:l", Sequence: 100}},
			{Position: types.LogPosition{LogDID: "did:web:l", Sequence: 101}},
		},
	}}
	fetcher := &delegFakeFetcher{bySeq: map[uint64][]byte{
		100: cosig1Bytes,
		101: cosig2Bytes,
	}}

	params, err := BuildPolicyStageParams(
		context.Background(), primary, schema, q, fetcher, nil,
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if params == nil {
		t.Fatal("expected non-nil params")
	}
	if params.Policy.Name != "concurring_2" {
		t.Errorf("Policy.Name = %q", params.Policy.Name)
	}
	if len(params.Candidates) != 2 {
		t.Fatalf("Candidates = %d, want 2", len(params.Candidates))
	}
	for i, c := range params.Candidates {
		if c.CanonicalBytes == nil {
			t.Errorf("Candidates[%d] not hydrated", i)
		}
	}
}

func TestBuildPolicyStageParams_PolicyNameNotFound(t *testing.T) {
	name := "unknown_policy"
	primary := types.EntryWithMetadata{
		Position:       types.LogPosition{LogDID: "did:web:l", Sequence: 1},
		CanonicalBytes: signedPrimaryBytes(t, "did:web:p", &name),
	}
	schema := &types.SchemaParameters{
		AttestationPolicies: []types.AttestationPolicy{
			{Name: "different", MinAttestors: 1},
		},
	}
	_, err := BuildPolicyStageParams(
		context.Background(), primary, schema, &fakeQuery{}, &delegFakeFetcher{}, nil,
	)
	if !errors.Is(err, ErrPolicyNameNotFound) {
		t.Errorf("err = %v, want errors.Is(ErrPolicyNameNotFound)", err)
	}
}

func TestBuildPolicyStageParams_InputGuards(t *testing.T) {
	bytes := signedPrimaryBytes(t, "did:web:p", nil)
	cases := []struct {
		name  string
		setup func() (types.EntryWithMetadata, *types.SchemaParameters, sdklog.LedgerQueryAPI, types.EntryFetcher)
		want  string
	}{
		{
			"missing canonical bytes",
			func() (types.EntryWithMetadata, *types.SchemaParameters, sdklog.LedgerQueryAPI, types.EntryFetcher) {
				return types.EntryWithMetadata{}, &types.SchemaParameters{}, &fakeQuery{}, &delegFakeFetcher{}
			},
			"CanonicalBytes",
		},
		{
			"nil schema params",
			func() (types.EntryWithMetadata, *types.SchemaParameters, sdklog.LedgerQueryAPI, types.EntryFetcher) {
				return types.EntryWithMetadata{CanonicalBytes: bytes}, nil, &fakeQuery{}, &delegFakeFetcher{}
			},
			"SchemaParameters",
		},
		{
			"nil query",
			func() (types.EntryWithMetadata, *types.SchemaParameters, sdklog.LedgerQueryAPI, types.EntryFetcher) {
				return types.EntryWithMetadata{CanonicalBytes: bytes}, &types.SchemaParameters{}, nil, &delegFakeFetcher{}
			},
			"LedgerQueryAPI",
		},
		{
			"nil fetcher",
			func() (types.EntryWithMetadata, *types.SchemaParameters, sdklog.LedgerQueryAPI, types.EntryFetcher) {
				return types.EntryWithMetadata{CanonicalBytes: bytes}, &types.SchemaParameters{}, &fakeQuery{}, nil
			},
			"EntryFetcher",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			primary, schema, q, f := c.setup()
			_, err := BuildPolicyStageParams(context.Background(), primary, schema, q, f, nil)
			if !errors.Is(err, ErrPolicyStage) {
				t.Errorf("err = %v, want errors.Is(ErrPolicyStage)", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want contains %q", err, c.want)
			}
		})
	}
}

func TestBuildPolicyStageParams_QueryErrorPropagates(t *testing.T) {
	name := "p"
	primary := types.EntryWithMetadata{
		Position:       types.LogPosition{LogDID: "did:web:l", Sequence: 1},
		CanonicalBytes: signedPrimaryBytes(t, "did:web:p", &name),
	}
	schema := &types.SchemaParameters{
		AttestationPolicies: []types.AttestationPolicy{{Name: "p", MinAttestors: 1}},
	}
	q := &fakeQuery{err: errors.New("ledger down")}
	_, err := BuildPolicyStageParams(context.Background(), primary, schema, q, &delegFakeFetcher{}, nil)
	if !errors.Is(err, ErrPolicyStage) {
		t.Errorf("err = %v, want errors.Is(ErrPolicyStage)", err)
	}
	if !strings.Contains(err.Error(), "cosignature_of") {
		t.Errorf("err = %v, want cosignature_of in message", err)
	}
}
