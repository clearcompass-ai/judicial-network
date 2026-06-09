package stack

import (
	"fmt"
	"os"
	"strings"
)

// Describe renders the resolved image set with, per image, whether the value
// came from an E2E_*_IMAGE override or the compiled-in default (naming the env
// var) — so an operator can SEE at a glance what is actually driving each
// container before anything is pulled. It also flags a tooling-fleet tag SKEW:
// ledger/witness/auditor must share ONE coordinated tag, because a mismatched
// ledger runs a different baseproof SDK — silently breaking the BP-ENTRY
// byte-match admission contract, and (if older) missing the SMT leaf-loss fix.
// Returns the banner and whether a skew was detected (a WARNING, not a hard
// stop — pinning a locally-built ledger against the released fleet is a valid
// dev workflow; the operator decides).
func (im Images) Describe() (banner string, skew bool) {
	rows := []struct{ role, envKey, value string }{
		{"postgres", "E2E_POSTGRES_IMAGE", im.Postgres},
		{"seaweedfs", "E2E_SEAWEED_IMAGE", im.Seaweed},
		{"ledger", "E2E_LEDGER_IMAGE", im.Ledger},
		{"witness", "E2E_WITNESS_IMAGE", im.Witness},
		{"auditor", "E2E_AUDITOR_IMAGE", im.Auditor},
		{"aggregator", "E2E_AGGREGATOR_IMAGE", im.Aggregator},
		{"jn", "E2E_JN_IMAGE", im.JN},
	}
	var b strings.Builder
	b.WriteString("== image resolution (what is driving each container) ==\n")
	for _, r := range rows {
		src := "default"
		if strings.TrimSpace(os.Getenv(r.envKey)) != "" {
			src = "OVERRIDE via " + r.envKey
		}
		fmt.Fprintf(&b, "  %-10s %s   [%s]\n", r.role, r.value, src)
	}
	if t := strings.TrimSpace(os.Getenv("E2E_TESSERA")); t != "" && !strings.EqualFold(t, "fork") {
		fmt.Fprintf(&b, "  %-10s %s   [OVERRIDE via E2E_TESSERA]\n", "tessera", t)
	}

	// Fleet-skew: the tooling trio must share one version tag (the -upstream
	// ledger variant compares equal to the fork witness/auditor).
	lt, wt, at := fleetTag(im.Ledger), fleetTag(im.Witness), fleetTag(im.Auditor)
	if lt != wt || wt != at {
		skew = true
		fmt.Fprintf(&b, "\n  ⚠ FLEET SKEW: ledger=%s witness=%s auditor=%s — MIXED tooling fleet.\n", lt, wt, at)
		b.WriteString("    ledger/witness/auditor must share ONE coordinated tag: a mismatched ledger\n")
		b.WriteString("    runs a different baseproof SDK (breaks the BP-ENTRY byte-match admission\n")
		b.WriteString("    contract) and, if older, lacks the current SMT fixes. Likely a stray\n")
		b.WriteString("    E2E_*_IMAGE override — `unset` it (or repin all three) and re-run.\n")
	}
	return b.String(), skew
}

// fleetTag returns a tooling image's version tag (the part after the last ':'),
// stripping the -upstream variant suffix so the fork and upstream ledger compare
// equal to witness/auditor. Returns the whole ref if it carries no tag.
func fleetTag(ref string) string {
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		return ref
	}
	return strings.TrimSuffix(ref[i+1:], "-upstream")
}
