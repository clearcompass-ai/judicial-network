/*
FILE PATH: cases/artifact/del_key_store_memory_test.go

DESCRIPTION:
    Contract pinning for the in-memory DelegationKeyStore reference
    impl. Asserts the store/get/delete invariants every backend
    must honor.
*/
package artifact

import (
	"bytes"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

func testCID(t *testing.T, b byte) storage.CID {
	t.Helper()
	return storage.Compute([]byte{b})
}

func TestInMemoryDelegationKeyStore_StoreGet_RoundTrip(t *testing.T) {
	ks := NewInMemoryDelegationKeyStore()
	cid := testCID(t, 0xAA)
	wrapped := []byte("wrapped-pre-delegation-key")
	if err := ks.Store(cid, wrapped); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := ks.Get(cid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, wrapped) {
		t.Errorf("got %x, want %x", got, wrapped)
	}
}

func TestInMemoryDelegationKeyStore_Get_ReturnsCopy(t *testing.T) {
	ks := NewInMemoryDelegationKeyStore()
	cid := testCID(t, 0xBB)
	original := []byte("original")
	if err := ks.Store(cid, original); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, _ := ks.Get(cid)
	got[0] = 'X' // mutate caller's copy
	got2, _ := ks.Get(cid)
	if got2[0] != 'o' {
		t.Errorf("Get returned aliased slice; mutation leaked into store: %s", got2)
	}
}

func TestInMemoryDelegationKeyStore_Get_Missing(t *testing.T) {
	ks := NewInMemoryDelegationKeyStore()
	if _, err := ks.Get(testCID(t, 0xCC)); !errors.Is(err, ErrDelKeyNotFound) {
		t.Errorf("expected ErrDelKeyNotFound, got %v", err)
	}
}

func TestInMemoryDelegationKeyStore_Store_RejectsEmpty(t *testing.T) {
	ks := NewInMemoryDelegationKeyStore()
	if err := ks.Store(testCID(t, 0xDD), nil); err == nil {
		t.Error("Store should reject empty wrapped key")
	}
}

func TestInMemoryDelegationKeyStore_Delete_Idempotent(t *testing.T) {
	ks := NewInMemoryDelegationKeyStore()
	cid := testCID(t, 0xEE)
	if err := ks.Delete(cid); err != nil {
		t.Errorf("Delete on missing should be no-op nil; got %v", err)
	}
	if err := ks.Store(cid, []byte("x")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := ks.Delete(cid); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if _, err := ks.Get(cid); !errors.Is(err, ErrDelKeyNotFound) {
		t.Errorf("Get after Delete should be ErrDelKeyNotFound; got %v", err)
	}
}

func TestInMemoryDelegationKeyStore_Store_Overwrite(t *testing.T) {
	ks := NewInMemoryDelegationKeyStore()
	cid := testCID(t, 0xFF)
	if err := ks.Store(cid, []byte("v1")); err != nil {
		t.Fatalf("Store v1: %v", err)
	}
	if err := ks.Store(cid, []byte("v2")); err != nil {
		t.Fatalf("Store v2: %v", err)
	}
	got, _ := ks.Get(cid)
	if string(got) != "v2" {
		t.Errorf("Store should overwrite; got %s", got)
	}
}
