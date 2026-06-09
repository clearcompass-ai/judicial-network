package stack

import (
	"strings"
	"testing"
)

// TestBackfillExitHint pins the failure diagnosis: a SIGKILL/OOM (137) or SIGTERM
// (143) must NOT be reported as a stale image, and "predates /backfill" must be
// reserved for the entrypoint-missing case (126/127) — the actual misdiagnosis
// that sent a 98%-complete OOM kill down the wrong path.
func TestBackfillExitHint(t *testing.T) {
	cases := []struct {
		code         string
		mustContain  string
		staleImageOK bool // may the hint mention "predates /backfill"?
	}{
		{"137", "SIGKILL", false},
		{"137", "OOM", false},
		{"143", "SIGTERM", false},
		{"125", "docker run", false},
		{"126", "predates /backfill", true},
		{"127", "predates /backfill", true},
		{"1", "WRITE path", false},
		{"2", "WRITE path", false},
	}
	for _, c := range cases {
		got := backfillExitHint(c.code)
		if !strings.Contains(got, c.mustContain) {
			t.Errorf("exit %s: hint %q must contain %q", c.code, got, c.mustContain)
		}
		if !c.staleImageOK && strings.Contains(got, "predates /backfill") {
			t.Errorf("exit %s: hint must NOT blame a stale image, got %q", c.code, got)
		}
	}
}
