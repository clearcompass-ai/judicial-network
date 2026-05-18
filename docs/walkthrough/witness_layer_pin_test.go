/*
FILE PATH: docs/walkthrough/witness_layer_pin_test.go

DESCRIPTION:

	Pins the attesta v1.5.x SDK types that back the walkthrough's
	Layer 3 (witness tree-head cosignatures) evidence section. If
	the SDK ever renames the witness-cosignature container or its
	signature element, this test surfaces the breakage at CI time
	so the walkthrough's evidence curls + the three-layer doc in
	02-real-dids.md can be updated in lock-step.

	# What we pin

	  1. types.CosignedTreeHead exists.
	  2. CosignedTreeHead embeds TreeHead (so RootHash + TreeSize
	     are accessible at the top level).
	  3. CosignedTreeHead has a non-empty signatures collection
	     field — Layer 3 evidence depends on iterating it.

	# Why this lives under docs/walkthrough/

	The walkthrough's Layer 3 evidence curl reads
	`.cosignatures[].signer_did` (and friends). If the ledger
	renames its JSON output OR the SDK renames the Go type the
	ledger marshals from, the walkthrough's curls fall apart. This
	test pins the SDK-side anchor; the ledger-side JSON shape is a
	separate contract owned by the ledger repo.
*/
package walkthrough_test

import (
	"reflect"
	"testing"

	"github.com/clearcompass-ai/attesta/types"
)

// TestWitnessLayer_SDKContract pins the SDK-side anchor that the
// walkthrough's Layer 3 (witness tree-head cosignatures) evidence
// section relies on.
//
// Failure mode example:
//
//	FAIL: types.CosignedTreeHead has no field named "Signatures"
//	      (or any reasonable witness-cosignature variant).
//	      Layer 3 walkthrough evidence steps will break.
//	      Update docs/walkthrough/02-real-dids.md "Three signature
//	      layers" section + every walkthrough's tree-head curl.
func TestWitnessLayer_SDKContract(t *testing.T) {
	// 1. types.CosignedTreeHead exists with the expected shape.
	cth := types.CosignedTreeHead{}
	cthT := reflect.TypeOf(cth)
	if cthT.Kind() != reflect.Struct {
		t.Fatalf("types.CosignedTreeHead kind = %s, want struct", cthT.Kind())
	}

	// 2. It embeds (or contains) types.TreeHead so callers can
	//    access RootHash + TreeSize directly.
	if _, embedded := cthT.FieldByName("TreeHead"); !embedded {
		t.Errorf("types.CosignedTreeHead is expected to embed TreeHead so RootHash + TreeSize are accessible at the top level; field not found. Walkthrough trial Step 6 reads `.size` and `.root_hash` from the tree-head response — flatten or rewire if this changes.")
	}

	// 3. There is a witness-cosignature collection field.
	//    Current SDK calls it "Signatures"; future renames should
	//    update both this test and the walkthrough's jq queries.
	sigsField, ok := cthT.FieldByName("Signatures")
	if !ok {
		t.Fatalf("types.CosignedTreeHead has no field named Signatures. The walkthrough's Layer 3 evidence step expects to iterate witness cosignatures via this field. If the SDK renamed the field, update 02-real-dids.md §\"Three signature layers\" Layer 3 + every tree-head jq query (.cosignatures[]) + this test.")
	}
	if sigsField.Type.Kind() != reflect.Slice {
		t.Errorf("CosignedTreeHead.Signatures kind = %s, want slice (witness operators are plural by design — quorum K can be > 1)", sigsField.Type.Kind())
	}

	// 4. The signature element type has a signer identity field —
	//    the walkthrough reads .signer_did from each cosignature.
	//    Confirm by reflection that the element struct has SOME
	//    field; we don't pin the exact name here because witness
	//    schemes may use DID, public-key, or operator-id forms.
	elemType := sigsField.Type.Elem()
	if elemType.Kind() != reflect.Struct {
		t.Errorf("CosignedTreeHead.Signatures element kind = %s, want struct (each witness signature is structured)", elemType.Kind())
	}
	if elemType.NumField() == 0 {
		t.Errorf("CosignedTreeHead.Signatures element struct %s has no fields — walkthrough Layer 3 evidence cannot iterate signer identity from an empty struct", elemType.Name())
	}
}

// TestWitnessLayer_DistinctFromEntrySigs is documentation as code:
// the three signature layers from 02-real-dids.md are distinct, and
// in particular the entry-level Signatures (Layer 1) and the
// tree-head Signatures (Layer 3) are different Go types. This test
// pins that distinction by reflection — anyone refactoring the SDK
// to unify them MUST also update the walkthrough's three-layer
// framing.
func TestWitnessLayer_DistinctFromEntrySigs(t *testing.T) {
	cth := reflect.TypeOf(types.CosignedTreeHead{})
	sigsField, _ := cth.FieldByName("Signatures")
	if sigsField.Type == nil {
		t.Skip("CosignedTreeHead.Signatures missing — covered by TestWitnessLayer_SDKContract")
	}
	witnessSigType := sigsField.Type.Elem().Name()

	// The entry-level signature struct (Layer 1) lives in
	// core/envelope; we don't import it here just to test by name.
	// What matters is that the WITNESS signature type isn't named
	// the same as a plausible entry-signature type, because if it
	// were the walkthrough's three-layer framing would collapse.
	confusable := map[string]bool{
		"Signature":      true,
		"EntrySignature": true,
	}
	if confusable[witnessSigType] {
		t.Errorf("CosignedTreeHead.Signatures element type is named %q — that's the same shape the entry-level Signatures uses, which means the walkthrough's Layer 1 vs Layer 3 distinction is at risk of conflation. Recommend keeping the witness signature type name distinct (e.g., WitnessSignature) to preserve the docs invariant.",
			witnessSigType)
	}
}
