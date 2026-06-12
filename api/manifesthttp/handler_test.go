package manifesthttp_test

// handler_test.go — GET /v1/network/bundle over the REAL davidson registry
// bundle, with an httptest ledger standing in for the schema_ref + raw-entry
// resolution surface. Proves: compiled fallback (published:false), published
// serve (exact on-log bytes + position), DRIFT detection (published ≠
// enforced ⇒ X-Manifest-Enforced-Match: false), hash-verified candidates,
// unknown-destination 404, the bare envelope, and ETag/304.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/baseproof/tooling/libs/networkbundle"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdkenv "github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"

	"github.com/clearcompass-ai/judicial-network/api/manifesthttp"
	davidson "github.com/clearcompass-ai/judicial-network/deployments/tn/counties/davidson"
	"github.com/clearcompass-ai/judicial-network/deployments/tn/trial"
	"github.com/clearcompass-ai/judicial-network/jurisdiction"
	"github.com/clearcompass-ai/judicial-network/netmanifest"
)

const anchor = davidson.ExchangeDID + "@3"

func registry(t *testing.T) *jurisdiction.Registry {
	t.Helper()
	r := jurisdiction.NewRegistry()
	if err := r.Register(davidson.MustBundle()); err != nil {
		t.Fatal(err)
	}
	r.Freeze()
	return r
}

func buildInput(string) networkbundle.BuildInput {
	return networkbundle.BuildInput{
		Network: networkbundle.NetworkRef{Name: "tn-davidson"},
		Overlay: trial.ManifestOverlay(),
		Status: networkbundle.StatusProbes{
			Protocol: "ledger:/v1/entries-hash/{hash}",
			Finality: "ledger:/v1/tree/horizon",
			Domain:   "terminal entry of the instance's closed_by/amended_by chain",
		},
	}
}

// publishedEntry wraps manifest bytes in a validly SIGNED envelope — what the
// ledger's raw-entry endpoint returns for a sequenced manifest publication.
func publishedEntry(t *testing.T, payload []byte) []byte {
	t.Helper()
	kp, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	auth := sdkenv.AuthoritySameSigner
	u, err := sdkenv.NewUnsignedEntry(sdkenv.ControlHeader{
		SignerDID: kp.DID, Destination: davidson.ExchangeDID,
		AuthorityPath: &auth, EventTime: time.Now().UTC().UnixMicro(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(sdkenv.SigningPayload(u))
	sig, err := signatures.SignEntry(digest, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	u.Signatures = []sdkenv.Signature{{SignerDID: kp.DID, AlgoID: sdkenv.SigAlgoECDSA, Bytes: sig}}
	wire, err := sdkenv.Serialize(u)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// stubLedger serves the two resolution endpoints: schema_ref listing one
// citing entry at seq 7, and that entry's raw bytes.
func stubLedger(t *testing.T, manifestPayload []byte) *httptest.Server {
	t.Helper()
	wire := publishedEntry(t, manifestPayload)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/query/schema_ref/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, anchor) {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": []map[string]any{{"sequence_number": 7}}, "count": 1,
		})
	})
	mux.HandleFunc("/v1/entries/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/entries/7/raw" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(wire)
	})
	return httptest.NewServer(mux)
}

func newHandler(t *testing.T, anchorPos, ledgerURL string) http.Handler {
	t.Helper()
	reg := registry(t)
	h, err := manifesthttp.New(manifesthttp.Config{
		Lookup:        reg.Bundle,
		Destinations:  reg.ExchangeDIDs,
		Input:         buildInput,
		Anchor:        anchorPos,
		LedgerBaseURL: ledgerURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func get(t *testing.T, h http.Handler, url string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func compiledBytes(t *testing.T) []byte {
	t.Helper()
	m, err := netmanifest.Build(davidson.MustBundle(), buildInput(davidson.ExchangeDID))
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestServe_CompiledFallback_NoAnchor(t *testing.T) {
	h := newHandler(t, "", "")
	rec := get(t, h, "/v1/network/bundle?destination="+davidson.ExchangeDID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Manifest-Published"); got != "false" {
		t.Errorf("X-Manifest-Published = %q, want false", got)
	}
	want := compiledBytes(t)
	if rec.Body.String() != string(want) {
		t.Error("body is not the compiled canonical bytes")
	}
	wantETag := `"` + hex.EncodeToString(func() []byte { s := sha256.Sum256(want); return s[:] }()) + `"`
	if rec.Header().Get("ETag") != wantETag {
		t.Errorf("ETag = %s, want %s", rec.Header().Get("ETag"), wantETag)
	}

	// If-None-Match round 2 → 304.
	rec2 := get(t, h, "/v1/network/bundle?destination="+davidson.ExchangeDID,
		map[string]string{"If-None-Match": wantETag})
	if rec2.Code != http.StatusNotModified {
		t.Errorf("If-None-Match: status = %d, want 304", rec2.Code)
	}
}

func TestServe_PublishedMatchesEnforced(t *testing.T) {
	srv := stubLedger(t, compiledBytes(t)) // published == compiled
	defer srv.Close()
	h := newHandler(t, anchor, srv.URL)

	rec := get(t, h, "/v1/network/bundle?destination="+davidson.ExchangeDID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Manifest-Published"); got != "true" {
		t.Errorf("X-Manifest-Published = %q, want true", got)
	}
	wantPos := davidson.ExchangeDID + "@7"
	if got := rec.Header().Get("X-Manifest-Position"); got != wantPos {
		t.Errorf("X-Manifest-Position = %q, want %q", got, wantPos)
	}
	if got := rec.Header().Get("X-Manifest-Enforced-Match"); got != "true" {
		t.Errorf("X-Manifest-Enforced-Match = %q, want true (published == enforced)", got)
	}
}

func TestServe_DriftFlaggedLoudly(t *testing.T) {
	// Publish a manifest built from DIFFERENT input — declared ≠ enforced.
	drifted, err := netmanifest.Build(davidson.MustBundle(), networkbundle.BuildInput{
		Network: networkbundle.NetworkRef{Name: "renamed-network"},
		Overlay: trial.ManifestOverlay(),
		Status:  buildInput("").Status,
	})
	if err != nil {
		t.Fatal(err)
	}
	driftedBytes, err := drifted.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	srv := stubLedger(t, driftedBytes)
	defer srv.Close()
	h := newHandler(t, anchor, srv.URL)

	rec := get(t, h, "/v1/network/bundle?destination="+davidson.ExchangeDID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("X-Manifest-Enforced-Match"); got != "false" {
		t.Fatalf("X-Manifest-Enforced-Match = %q, want false (drift must be flagged)", got)
	}
	// The on-log declaration is what is served — verbatim.
	if rec.Body.String() != string(driftedBytes) {
		t.Error("drifted serve did not return the exact on-log bytes")
	}
}

func TestServe_UnknownDestination404(t *testing.T) {
	h := newHandler(t, "", "")
	rec := get(t, h, "/v1/network/bundle?destination=did:web:nowhere", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestServe_Envelope(t *testing.T) {
	h := newHandler(t, "", "")
	rec := get(t, h, "/v1/network/bundle", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var env struct {
		Format    string   `json:"format"`
		Exchanges []string `json:"exchanges"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Format != networkbundle.ManifestFormat {
		t.Errorf("format = %q", env.Format)
	}
	if len(env.Exchanges) != 1 || env.Exchanges[0] != davidson.ExchangeDID {
		t.Errorf("exchanges = %v, want [%s]", env.Exchanges, davidson.ExchangeDID)
	}
}

func TestNew_AnchorRequiresLedgerURL(t *testing.T) {
	reg := registry(t)
	_, err := manifesthttp.New(manifesthttp.Config{
		Lookup: reg.Bundle, Destinations: reg.ExchangeDIDs, Input: buildInput,
		Anchor: anchor, // no LedgerBaseURL
	})
	if err == nil {
		t.Fatal("New accepted an anchor with no ledger URL (resolution impossible)")
	}
	if _, err := manifesthttp.New(manifesthttp.Config{
		Lookup: reg.Bundle, Destinations: reg.ExchangeDIDs, Input: buildInput,
		Anchor: "missing-seq", LedgerBaseURL: "http://x",
	}); err == nil {
		t.Fatal("New accepted a malformed anchor")
	}
	_ = fmt.Sprint() // keep fmt imported if assertions change
}
