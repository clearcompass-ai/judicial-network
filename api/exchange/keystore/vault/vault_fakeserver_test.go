/*
FILE PATH: api/exchange/keystore/vault/vault_fakeserver_test.go

DESCRIPTION:

	Mock Vault Transit server for unit tests. Implements the subset
	of /v1/transit endpoints the keystore exercises (create / read /
	sign / rotate / delete) with REAL secp256k1 + Ed25519 keys so
	SignSecp256k1 round-trips through actual ASN.1 marshal/unmarshal
	+ recovery-byte selection.
*/
package vault

import (
	stdlibecdsa "crypto/ecdsa"
	"crypto/ed25519"
	stdliberand "crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// fakeVault holds one secp256k1 + one ed25519 key per name and
// answers create / read / sign / rotate / delete the way Vault Transit
// does.
type fakeVault struct {
	t       *testing.T
	secKeys map[string]*secp256k1.PrivateKey
	edKeys  map[string]ed25519.PrivateKey
}

func newFakeVault(t *testing.T) *httptest.Server {
	fv := &fakeVault{
		t:       t,
		secKeys: map[string]*secp256k1.PrivateKey{},
		edKeys:  map[string]ed25519.PrivateKey{},
	}
	return httptest.NewServer(http.HandlerFunc(fv.serve))
}

func (fv *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("X-Vault-Token"); got != "test-token" {
		http.Error(w, "bad token", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/transit/keys/") && strings.HasSuffix(r.URL.Path, "/rotate"):
		fv.handleRotate(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/transit/keys/"):
		fv.handleCreate(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/transit/keys/"):
		fv.handleRead(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/transit/keys/"):
		fv.handleDelete(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/transit/sign/"):
		fv.handleSign(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (fv *fakeVault) handleCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/transit/keys/")
	var body struct {
		Type string `json:"type"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	switch body.Type {
	case "ecdsa-p256k1":
		priv, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		fv.secKeys[name] = priv
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(stdliberand.Reader)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		fv.edKeys[name] = priv
	default:
		http.Error(w, "unknown type", 400)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (fv *fakeVault) handleRead(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/transit/keys/")
	var der []byte
	var err error
	if priv, ok := fv.secKeys[name]; ok {
		// Hand-roll the SubjectPublicKeyInfo for secp256k1 since
		// crypto/x509 won't marshal an unknown curve.
		spki := struct {
			Algo struct {
				Algorithm  asn1.ObjectIdentifier
				Parameters asn1.ObjectIdentifier
			}
			PubKey asn1.BitString
		}{}
		spki.Algo.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
		spki.Algo.Parameters = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
		spki.PubKey = asn1.BitString{Bytes: priv.PubKey().SerializeUncompressed(), BitLength: 8 * 65}
		der, err = asn1.Marshal(spki)
	} else if priv, ok := fv.edKeys[name]; ok {
		der, err = x509.MarshalPKIXPublicKey(priv.Public().(ed25519.PublicKey))
	} else {
		http.Error(w, "no key", 404)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	resp := map[string]any{
		"data": map[string]any{
			"latest_version": 1,
			"keys": map[string]any{
				"1": map[string]any{"public_key": pemStr},
			},
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (fv *fakeVault) handleSign(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/transit/sign/")
	var body struct {
		Input string `json:"input"`
	}
	raw, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(raw, &body)
	digest, _ := base64.StdEncoding.DecodeString(body.Input)
	var sig string
	if priv, ok := fv.secKeys[name]; ok {
		stdPriv := &stdlibecdsa.PrivateKey{
			PublicKey: stdlibecdsa.PublicKey{
				Curve: secp256k1.S256(),
				X:     new(big.Int).SetBytes(priv.PubKey().SerializeUncompressed()[1:33]),
				Y:     new(big.Int).SetBytes(priv.PubKey().SerializeUncompressed()[33:65]),
			},
			D: new(big.Int).SetBytes(priv.Serialize()),
		}
		rr, ss, err := stdlibecdsa.Sign(stdliberand.Reader, stdPriv, digest)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		der, _ := asn1.Marshal(struct{ R, S *big.Int }{rr, ss})
		sig = "vault:v1:" + base64.StdEncoding.EncodeToString(der)
	} else if priv, ok := fv.edKeys[name]; ok {
		out := ed25519.Sign(priv, digest)
		sig = "vault:v1:" + base64.StdEncoding.EncodeToString(out)
	} else {
		http.Error(w, "no key", 404)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"signature": sig}})
}

func (fv *fakeVault) handleRotate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/transit/keys/"), "/rotate")
	if _, ok := fv.secKeys[name]; ok {
		priv, _ := secp256k1.GeneratePrivateKey()
		fv.secKeys[name] = priv
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Error(w, "no key", 404)
}

func (fv *fakeVault) handleDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/transit/keys/")
	delete(fv.secKeys, name)
	delete(fv.edKeys, name)
	w.WriteHeader(http.StatusNoContent)
}

// newKS spins up a fakeVault and returns a wired KeyStore + the
// httptest.Server so callers can defer Close.
func newKS(t *testing.T) (*KeyStore, *httptest.Server) {
	srv := newFakeVault(t)
	ks, err := New(Config{Address: srv.URL, Token: "test-token", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ks, srv
}
