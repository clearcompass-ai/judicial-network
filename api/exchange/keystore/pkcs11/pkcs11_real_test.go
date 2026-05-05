//go:build pkcs11

/*
FILE PATH: api/exchange/keystore/pkcs11/pkcs11_real_test.go

DESCRIPTION:

	Real-token PKCS#11 conformance test. Built only with `-tags pkcs11`
	AND when SOFTHSM_LIB + SOFTHSM_PIN are present in the environment;
	otherwise the test skips. Run locally with:

	  export SOFTHSM2_CONF=$PWD/softhsm.conf
	  softhsm2-util --init-token --slot 0 --label test --pin 1234 --so-pin 1234
	  SOFTHSM_LIB=/usr/lib/softhsm/libsofthsm2.so SOFTHSM_PIN=1234 \
	    SOFTHSM_SLOT=$(softhsm2-util --show-slots | awk '/^Slot/{slot=$2} /Initialized:.*yes/{print slot; exit}') \
	    go test -tags pkcs11 ./api/exchange/keystore/pkcs11/...

	The test exercises the same RunSecp256k1Conformance suite the
	Vault and Memory backends pass, so wire shapes are guaranteed
	interchangeable across all three production backends.
*/
package pkcs11

import (
	"os"
	"strconv"
	"testing"

	"github.com/clearcompass-ai/judicial-network/api/exchange/keystore"
)

func TestPKCS11_RealToken_Conformance(t *testing.T) {
	lib := os.Getenv("SOFTHSM_LIB")
	pin := os.Getenv("SOFTHSM_PIN")
	if lib == "" || pin == "" {
		t.Skip("SOFTHSM_LIB and SOFTHSM_PIN must both be set; run against a provisioned SoftHSMv2 token")
	}
	slot := uint(0)
	if s := os.Getenv("SOFTHSM_SLOT"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("SOFTHSM_SLOT parse: %v", err)
		}
		slot = uint(v)
	}
	ks, err := New(Config{LibraryPath: lib, SlotID: slot, PIN: pin})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer ks.Close()

	keystore.RunSecp256k1Conformance(t, ks)
}

func TestPKCS11_New_RequiresLibrary(t *testing.T) {
	if _, err := New(Config{PIN: "x"}); err == nil {
		t.Error("expected error for missing library path")
	}
}

func TestPKCS11_New_RequiresPIN(t *testing.T) {
	if _, err := New(Config{LibraryPath: "/lib"}); err == nil {
		t.Error("expected error for missing PIN")
	}
}

func TestPKCS11_LoadPINFile_Missing(t *testing.T) {
	if _, err := LoadPINFile("/no/such/file/__"); err == nil {
		t.Error("expected error for missing PIN file")
	}
}

func TestPKCS11_Ed25519_AlwaysFails(t *testing.T) {
	ks := &KeyStore{}
	if _, err := ks.Generate("did", "signing"); err != ErrEd25519Unsupported {
		t.Errorf("Generate err = %v, want ErrEd25519Unsupported", err)
	}
	if _, err := ks.Sign("did", []byte("x")); err != ErrEd25519Unsupported {
		t.Errorf("Sign err = %v, want ErrEd25519Unsupported", err)
	}
	if _, err := ks.PublicKey("did"); err != ErrEd25519Unsupported {
		t.Errorf("PublicKey err = %v, want ErrEd25519Unsupported", err)
	}
}

func TestPKCS11_ExportForEscrow_Refuses(t *testing.T) {
	ks := &KeyStore{}
	if _, err := ks.ExportForEscrow("did"); err == nil {
		t.Error("expected ExportForEscrow to refuse")
	}
}

func TestPKCS11_LeftPad32(t *testing.T) {
	if got := leftPad32([]byte{1, 2, 3}); len(got) != 32 || got[29] != 1 {
		t.Errorf("leftPad32 wrong: %x", got)
	}
}
