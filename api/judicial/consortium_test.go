/*
FILE PATH: api/judicial/consortium_test.go

DESCRIPTION:

	Validation contracts for the consortium handlers
	(propose-addition, propose-removal, cross-court-proof verify,
	plus the five 501-stubbed federation endpoints).
*/
package judicial

import (
	"bytes"
	"context"
	"errors"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
	"github.com/clearcompass-ai/judicial-network/verification/eras"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────
// propose-addition / propose-removal
// ─────────────────────────────────────────────────────────────────────

func TestConsortiumProposeAddition_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, consortiumProposalRequest{TargetDID: "did:web:other"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/members/propose-addition", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestConsortiumProposeAddition_MissingTarget_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, consortiumProposalRequest{CourtName: "Davidson"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/members/propose-addition", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestConsortiumProposeAddition_HappyPath(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, consortiumProposalRequest{
		Destination: "did:web:consortium:tn:trial-courts",
		TargetDID:   "did:web:state:tn:williamson",
		CourtName:   "Williamson County",
		Reason:      "joining state-wide cohort",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/members/propose-addition", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestConsortiumProposeRemoval_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, consortiumProposalRequest{TargetDID: "did:web:other"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/members/propose-removal", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestConsortiumProposeRemoval_MissingTarget_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, consortiumProposalRequest{Reason: "no target"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/members/propose-removal", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestConsortiumProposeRemoval_HappyPath(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := mustJSON(t, consortiumProposalRequest{
		Destination: "did:web:consortium:tn:trial-courts",
		TargetDID:   "did:web:state:tn:williamson",
		CourtName:   "Williamson County",
		Reason:      "withdrawal at request of court administrator",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/members/propose-removal", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────
// cross-court-proof/verify
// ─────────────────────────────────────────────────────────────────────

func TestConsortiumVerifyCrossCourt_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	body := []byte(`{"proof":{}, "source_log_did":"did:web:state:tn:williamson:cases"}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/cross-court-proof/verify", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// v0.3.0+: the BLS verifier moved inside WitnessKeySet. The
// FED-1 #107: the failure modes are now era-resolution classes —
// an unknown source log is a config-class 400 (no trust root); an
// unconfigured resolver is a wiring-class 500, never a panic.
func TestConsortiumVerifyCrossCourt_NoTrustRoot_400(t *testing.T) {
	withCaller(t, testJudge)
	noPeers, err := eras.New(refusingInner{}, emptyChains{}, nil, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandler(Dependencies{Eras: noPeers})
	body := []byte(`{"proof":{}, "source_log_did":"did:web:state:tn:williamson:cases"}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/cross-court-proof/verify", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (no trust root for source log)", rec.Code)
	}
}

func TestConsortiumVerifyCrossCourt_NoResolver_500_NeverPanics(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := []byte(`{"proof":{}, "source_log_did":"did:web:state:tn:williamson:cases"}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/cross-court-proof/verify", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (era resolution not configured)", rec.Code)
	}
}

// refusingInner / emptyChains: minimal fakes for the class tests.
type refusingInner struct{}

func (refusingInner) SetForHead(context.Context, string, types.CosignedTreeHead) (*cosign.WitnessKeySet, error) {
	return nil, errNoChain
}
func (refusingInner) CurrentSet(context.Context, string) (*cosign.WitnessKeySet, error) {
	return nil, errNoChain
}

var errNoChain = errors.New("no chain")

type emptyChains struct{}

func (emptyChains) RecordsFor(context.Context, string) ([]types.WitnessRotationRecord, error) {
	return nil, nil
}

func TestConsortiumVerifyCrossCourt_MissingFields_400(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	body := []byte(`{"proof":{}}`) // missing source_log_did
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/cross-court-proof/verify", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestConsortiumVerifyCrossCourt_NoWitnessKeys_400(t *testing.T) {
	withCaller(t, testJudge)
	noPeers, err := eras.New(refusingInner{}, emptyChains{}, nil, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandler(Dependencies{Eras: noPeers})
	body := []byte(`{"proof":{}, "source_log_did":"did:web:state:tn:williamson:cases"}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/cross-court-proof/verify", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// 501 stubs
// ─────────────────────────────────────────────────────────────────────

func TestConsortiumBuildCrossCourt_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/cross-court-proof/build", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestConsortiumBuildCrossCourt_NotImplemented(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/cross-court-proof/build", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}

func TestConsortiumExecuteAdd_NotImplemented(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/members/execute-addition", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}

func TestConsortiumExecuteAdd_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/members/execute-addition", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestConsortiumExecuteRemove_NotImplemented(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/members/execute-removal", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}

func TestConsortiumExecuteRemove_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/members/execute-removal", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestConsortiumActivateRemoval_NotImplemented(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/members/activate-removal", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}

func TestConsortiumActivateRemoval_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/members/activate-removal", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestConsortiumFormation_NotImplemented(t *testing.T) {
	withCaller(t, testJudge)
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/formation", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}

func TestConsortiumFormation_NoCaller_401(t *testing.T) {
	h := newTestHandler(Dependencies{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/v1/judicial/consortium/formation", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}
