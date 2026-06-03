//go:build e2e

// Phase 3 — Auditor wire contract (L9), SCENARIOS.md.
package ledger

import (
	"testing"

	"github.com/clearcompass-ai/judicial-network/e2e/tests/harness"
)

// S3.1 — Health + readiness + version. (The no-DSN health-only mode is a
// separate deployment; here we assert the running auditor.)
func TestS3_1_HealthReadyVersion(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireAuditor(t)
	code, body, _ := s.Auditor.Health()
	harness.Eq(t, code, 200, "auditor /healthz status")
	harness.Eq(t, body, "ok", "auditor /healthz body")
	rc, _, _ := s.Auditor.Ready()
	harness.StatusIn(t, rc, "auditor /readyz status", 200, 503)
	_, vc, _ := s.Auditor.Version()
	harness.StatusIn(t, vc, "auditor /version status", 200, 404)
}

// S3.2 — Gossip feed shape + cursor.
func TestS3_2_GossipFeedShape(t *testing.T) {
	s := harness.NewStack(t)
	s.RequireAuditor(t)
	code, body, err := s.Auditor.GossipSince("0", 50)
	harness.Truthy(t, err == nil, "auditor gossip error: "+harness.ErrStr(err))
	harness.Eq(t, code, 200, "auditor /v1/gossip/since status")
	harness.ValidJSON(t, body, "auditor gossip since")
}

// S3.3 — Custody chain discipline: asserted end-to-end by S6.3 (the auditor
// re-verifies + persists what it pulls). Anchor keeps the ID present.
func TestS3_3_CustodyChain(t *testing.T) {
	t.Skip("covered end-to-end by S6.3 (ledger→auditor re-verify + persist)")
}

// S3.4 — Peer allowlist fail-closed: needs the auditor pointed at a
// non-allowlisted peer (a reconfigured deployment variant).
func TestS3_4_PeerAllowlistFailClosed(t *testing.T) {
	s := harness.NewStack(t)
	s.Pending(t, "S3.4 needs an auditor reconfigured with a non-allowlisted peer (deployment variant)")
}

// S3.5 — Retention prune: time-based; needs AUDITOR_GOSSIP_RETENTION_DAYS and
// an elapsed window.
func TestS3_5_RetentionPrune(t *testing.T) {
	s := harness.NewStack(t)
	s.Pending(t, "S3.5 needs AUDITOR_GOSSIP_RETENTION_DAYS + elapsed retention window (long-running variant)")
}
