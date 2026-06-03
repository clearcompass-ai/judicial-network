package rotation

import "testing"

// UC-ROT-4 / year-1 vs year-15: a PROVABLE multi-era history reconstructs the
// era-correct witness set at any historical position (and rejects a null as-of).
func TestUC_ROT_4_VerifiedHistory_EraCorrect(t *testing.T) {
	e, err := Eras(15, 4, 3, "rotation-history-year1-15")
	if err != nil {
		t.Fatalf("Eras: %v", err)
	}
	AssertVerifiedHistoryEraCorrect(t, e, "did:web:rotation-history.test")
}
