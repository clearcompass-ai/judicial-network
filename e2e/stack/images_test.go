package stack

import (
	"strings"
	"testing"
)

// fleetImageDefaults clears the E2E_*_IMAGE overrides so a test asserts the
// compiled-in defaults rather than an ambient environment.
func clearImageEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"E2E_TESSERA", "E2E_LEDGER_IMAGE", "E2E_WITNESS_IMAGE", "E2E_AUDITOR_IMAGE",
		"E2E_AGGREGATOR_IMAGE", "E2E_JN_IMAGE",
	} {
		t.Setenv(k, "")
	}
}

// TestResolveImages_Namespaces locks the post-relocation image contract:
//   - the tooling fleet (ledger/witness/auditor) publishes under
//     ghcr.io/baseproof/tooling at the new 0.0.1 lineage;
//   - JN's own images (aggregator, JN) stay under
//     ghcr.io/clearcompass-ai/judicial-network.
//
// A mixed fleet (old attesta-tools images against the baseproof-SDK JN) breaks
// the BP-ENTRY-/X-Baseproof- byte-match admission contract, and a stale tag is a
// hard "image not found" at bring-up — so both the namespace AND the tag matter.
func TestResolveImages_Namespaces(t *testing.T) {
	clearImageEnv(t)
	im := ResolveImages()

	relocated := map[string]string{
		"ledger":  im.Ledger,
		"witness": im.Witness,
		"auditor": im.Auditor,
	}
	for svc, ref := range relocated {
		if want := "ghcr.io/baseproof/tooling/" + svc + ":0.1.2"; ref != want {
			t.Errorf("%s image = %q, want %q (relocated fleet, 0.1.2 release)", svc, ref, want)
		}
		if strings.Contains(ref, "attesta-tools") || strings.Contains(ref, "clearcompass-ai") {
			t.Errorf("%s image %q still references the retired namespace", svc, ref)
		}
	}

	own := map[string]string{"aggregator": im.Aggregator, "jn": im.JN}
	for svc, ref := range own {
		if !strings.HasPrefix(ref, "ghcr.io/clearcompass-ai/judicial-network") {
			t.Errorf("%s image %q: want ghcr.io/clearcompass-ai/judicial-network* (JN-owned, not relocated)", svc, ref)
		}
		if strings.Contains(ref, "baseproof/tooling") {
			t.Errorf("%s image %q was wrongly relocated — JN owns its images", svc, ref)
		}
	}
}

// TestResolveImages_TesseraUpstream proves the upstream selector suffixes the
// ledger variant under the new namespace/tag (ghcr's 0.1.2-upstream tag).
func TestResolveImages_TesseraUpstream(t *testing.T) {
	clearImageEnv(t)
	t.Setenv("E2E_TESSERA", "upstream")
	im := ResolveImages()
	if want := "ghcr.io/baseproof/tooling/ledger:0.1.2-upstream"; im.Ledger != want {
		t.Errorf("upstream ledger = %q, want %q", im.Ledger, want)
	}
	// Only the ledger has an upstream variant; witness/auditor are unaffected.
	if want := "ghcr.io/baseproof/tooling/witness:0.1.2"; im.Witness != want {
		t.Errorf("witness = %q, want %q (no upstream suffix)", im.Witness, want)
	}
}

// TestResolveImages_EnvOverride proves an explicit E2E_*_IMAGE still wins, so an
// operator can repin without a code change.
func TestResolveImages_EnvOverride(t *testing.T) {
	clearImageEnv(t)
	t.Setenv("E2E_LEDGER_IMAGE", "ghcr.io/baseproof/tooling/ledger:9.9.9")
	if got := ResolveImages().Ledger; got != "ghcr.io/baseproof/tooling/ledger:9.9.9" {
		t.Errorf("override ledger = %q, want the explicit pin", got)
	}
}
