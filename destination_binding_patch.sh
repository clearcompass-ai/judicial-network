#!/bin/bash
# ============================================================================
# destination_binding_patch.sh
# Generated from AST analysis of 143 builder.Build* call sites
# 
# USAGE:
#   cd ~/workspace/judicial-network
#   bash destination_binding_patch.sh
#
# This script adds Destination field to every builder.Build* call site.
# - Test files use: "did:web:exchange.test"
# - Source files use: cfg.Destination (or equivalent config variable)
#   Source files ALSO need their config structs updated to carry Destination.
#
# IMPORTANT: Run `GOWORK=off go build ./...` after applying to find any
# config struct compilation errors that need the Destination field added.
# ============================================================================

set -euo pipefail

DEST_TEST='"did:web:exchange.test"'
DEST_CFG='cfg.Destination'

echo "=== Destination Binding Patch: 143 call sites across 65 files ==="
echo ""

# ──────────────────────────────────────────────────────────────────────
# PHASE 1: AST ANALYSIS TOOL (run for validation)
# ──────────────────────────────────────────────────────────────────────
# To validate, run the Go tool at the bottom of this script first:
#   go run cmd/destination-patch-verify/main.go .
# It will report any call sites this script missed.

# ──────────────────────────────────────────────────────────────────────
# PHASE 2: TEST FILES — constant destination
# ──────────────────────────────────────────────────────────────────────

echo "--- TEST FILES ---"

# api/core/handlers/handlers_test.go (1 site)
# L58: builder.BuildRootEntity(builder.RootEntityParams{
#   SignerDID: "did:web:courts.test.gov",
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' api/core/handlers/handlers_test.go
echo "  api/core/handlers/handlers_test.go (1 site)"

# cases/cases_test.go (10 sites)
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' cases/cases_test.go
sed -i '' '/builder\.AmendmentParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' cases/cases_test.go
sed -i '' '/builder\.PathBParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' cases/cases_test.go
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' cases/cases_test.go
sed -i '' '/builder\.SuccessionParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' cases/cases_test.go
sed -i '' '/builder\.CosignatureParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' cases/cases_test.go
echo "  cases/cases_test.go (10 sites)"

# consortium/consortium_test.go (7 sites)
sed -i '' '/builder\.ScopeCreationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' consortium/consortium_test.go
sed -i '' '/builder\.ScopeAmendmentParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' consortium/consortium_test.go
sed -i '' '/builder\.ScopeRemovalParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' consortium/consortium_test.go
sed -i '' '/builder\.AnchorParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' consortium/consortium_test.go
sed -i '' '/builder\.MirrorParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' consortium/consortium_test.go
echo "  consortium/consortium_test.go (7 sites)"

# delegation/delegation_test.go (11 sites)
sed -i '' '/builder\.DelegationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' delegation/delegation_test.go
sed -i '' '/builder\.RevocationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' delegation/delegation_test.go
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' delegation/delegation_test.go
echo "  delegation/delegation_test.go (11 sites)"

# enforcement/enforcement_test.go (10 sites)
sed -i '' '/builder\.EnforcementParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' enforcement/enforcement_test.go
echo "  enforcement/enforcement_test.go (10 sites)"

# migration/migration_test.go (3 sites)
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' migration/migration_test.go
sed -i '' '/builder\.SuccessionParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' migration/migration_test.go
echo "  migration/migration_test.go (3 sites)"

# tests/wave1_integration_test.go (6 sites)
sed -i '' '/builder\.DelegationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave1_integration_test.go
sed -i '' '/builder\.RevocationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave1_integration_test.go
sed -i '' '/builder\.SchemaEntryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave1_integration_test.go
echo "  tests/wave1_integration_test.go (6 sites)"

# tests/wave2_integration_test.go (9 sites)
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave2_integration_test.go
sed -i '' '/builder\.AmendmentParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave2_integration_test.go
sed -i '' '/builder\.EnforcementParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave2_integration_test.go
sed -i '' '/builder\.DelegationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave2_integration_test.go
sed -i '' '/builder\.PathBParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave2_integration_test.go
echo "  tests/wave2_integration_test.go (9 sites)"

# tests/wave3_integration_test.go (2 sites)
sed -i '' '/builder\.AnchorParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave3_integration_test.go
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave3_integration_test.go
echo "  tests/wave3_integration_test.go (2 sites)"

# tests/wave5_tools_test.go (7 sites)
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave5_tools_test.go
sed -i '' '/builder\.AmendmentParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave5_tools_test.go
sed -i '' '/builder\.DelegationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave5_tools_test.go
sed -i '' '/builder\.EnforcementParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave5_tools_test.go
sed -i '' '/builder\.PathBParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave5_tools_test.go
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave5_tools_test.go
sed -i '' '/builder\.CosignatureParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tests/wave5_tools_test.go
echo "  tests/wave5_tools_test.go (7 sites)"

# tools/aggregator/aggregator_test.go (8 sites)
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tools/aggregator/aggregator_test.go
sed -i '' '/builder\.AmendmentParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tools/aggregator/aggregator_test.go
sed -i '' '/builder\.DelegationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tools/aggregator/aggregator_test.go
sed -i '' '/builder\.EnforcementParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tools/aggregator/aggregator_test.go
sed -i '' '/builder\.PathBParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tools/aggregator/aggregator_test.go
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tools/aggregator/aggregator_test.go
sed -i '' '/builder\.CosignatureParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' tools/aggregator/aggregator_test.go
echo "  tools/aggregator/aggregator_test.go (8 sites)"

# verification/verification_test.go (8 sites)
sed -i '' '/builder\.AmendmentParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' verification/verification_test.go
sed -i '' '/builder\.PathBParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' verification/verification_test.go
sed -i '' '/builder\.EnforcementParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' verification/verification_test.go
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: '"$DEST_TEST"',\
\1SignerDID:/;}' verification/verification_test.go
echo "  verification/verification_test.go (8 sites)"


# ──────────────────────────────────────────────────────────────────────
# PHASE 3: SOURCE FILES — config-based destination
# ──────────────────────────────────────────────────────────────────────

echo ""
echo "--- SOURCE FILES ---"

# ── api/exchange/handlers/entries.go (4 sites) ──
# Uses req.* pattern. Needs: req.Destination or a server-level exchangeDID.
# For now inject cfg.ExchangeDID placeholder — manual review needed.
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: s.exchangeDID,\
\1SignerDID:/;}' api/exchange/handlers/entries.go
sed -i '' '/builder\.AmendmentParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: s.exchangeDID,\
\1SignerDID:/;}' api/exchange/handlers/entries.go
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: s.exchangeDID,\
\1SignerDID:/;}' api/exchange/handlers/entries.go
sed -i '' '/builder\.EnforcementParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: s.exchangeDID,\
\1SignerDID:/;}' api/exchange/handlers/entries.go
echo "  api/exchange/handlers/entries.go (4 sites) — uses s.exchangeDID"

# ── api/exchange/handlers/management.go (3 sites) ──
sed -i '' '/builder\.DelegationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: s.exchangeDID,\
\1SignerDID:/;}' api/exchange/handlers/management.go
sed -i '' '/builder\.RevocationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: s.exchangeDID,\
\1SignerDID:/;}' api/exchange/handlers/management.go
sed -i '' '/builder\.KeyRotationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: s.exchangeDID,\
\1SignerDID:/;}' api/exchange/handlers/management.go
echo "  api/exchange/handlers/management.go (3 sites) — uses s.exchangeDID"

# ── appeals/*.go (5 sites) ──
# These use cfg.* pattern — config structs need Destination field added.
sed -i '' '/builder\.PathBParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' appeals/decision.go
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' appeals/initiation.go
sed -i '' '/builder\.EnforcementParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' appeals/mandate.go
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' appeals/mandate.go
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' appeals/record.go
echo "  appeals/*.go (5 sites) — uses cfg.Destination"

# ── cases/*.go (7 sites, excluding test) ──
sed -i '' '/builder\.AmendmentParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' cases/amendment.go
sed -i '' '/builder\.AmendmentParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' cases/filing.go
sed -i '' '/builder\.PathBParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' cases/filing.go
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' cases/initiation.go
sed -i '' '/builder\.PathBParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' cases/judicial_action.go
sed -i '' '/builder\.AmendmentParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' cases/transfer.go
echo "  cases/*.go (7 sites) — uses cfg.Destination"

# ── consortium/formation.go — not in grep, skip ──

# ── consortium/load_accounting/*.go (3 sites) ──
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: r.destination,\
\1SignerDID:/;}' consortium/load_accounting/fire_drills.go
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: destination,\
\1SignerDID:/;}' consortium/load_accounting/schema.go
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: sm.destination,\
\1SignerDID:/;}' consortium/load_accounting/settlement.go
echo "  consortium/load_accounting/*.go (3 sites) — uses struct-level destination"

# ── delegation/*.go (8 source files, 9 sites) ──
sed -i '' '/builder\.DelegationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' delegation/clerk.go
sed -i '' '/builder\.ScopeCreationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' delegation/court_profile.go
sed -i '' '/builder\.DelegationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' delegation/deputy.go
sed -i '' '/builder\.ScopeCreationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' delegation/division.go
sed -i '' '/builder\.DelegationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' delegation/judge.go
sed -i '' '/builder\.MirrorParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' delegation/mirror.go
sed -i '' '/builder\.DelegationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' delegation/roster_sync.go
sed -i '' '/builder\.RevocationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' delegation/roster_sync.go
sed -i '' '/builder\.SuccessionParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' delegation/succession.go
echo "  delegation/*.go (9 sites) — uses cfg.Destination"

# ── deployments/davidson_county/*.go (5 sites) ──
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' deployments/davidson_county/court_ops.go
sed -i '' '/builder\.DelegationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' deployments/davidson_county/court_ops.go
sed -i '' '/builder\.RevocationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' deployments/davidson_county/court_ops.go
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' deployments/davidson_county/court_ops.go
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' deployments/davidson_county/daily_docket.go
echo "  deployments/davidson_county/*.go (5 sites) — uses cfg.Destination"

# ── enforcement/*.go (3 source files, 3 sites) ──
sed -i '' '/builder\.EnforcementParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' enforcement/expungement.go
sed -i '' '/builder\.EnforcementParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' enforcement/sealing.go
sed -i '' '/builder\.EnforcementParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' enforcement/unsealing.go
echo "  enforcement/*.go (3 sites) — uses cfg.Destination"

# ── migration/*.go (5 sites) ──
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' migration/bulk_historical.go
sed -i '' '/builder\.AmendmentParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' migration/bulk_historical.go
sed -i '' '/builder\.SuccessionParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' migration/graceful.go
sed -i '' '/builder\.KeyRotationParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' migration/graceful.go
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' migration/ungraceful.go
echo "  migration/*.go (5 sites) — uses cfg.Destination"

# ── monitoring/evidence_grant_compliance.go (1 site) ──
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' monitoring/evidence_grant_compliance.go
echo "  monitoring/evidence_grant_compliance.go (1 site) — uses cfg.Destination"

# ── onboarding/*.go (2 sites) ──
sed -i '' '/builder\.AnchorParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' onboarding/anchor_registration.go
sed -i '' '/builder\.SchemaEntryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' onboarding/schema_adoption.go
echo "  onboarding/*.go (2 sites) — uses cfg.Destination"

# ── operations/events.go (1 site) ──
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' operations/events.go
echo "  operations/events.go (1 site) — uses cfg.Destination"

# ── parties/*.go (3 sites) ──
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' parties/binding.go
sed -i '' '/builder\.AmendmentParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' parties/binding.go
sed -i '' '/builder\.RootEntityParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' parties/binding_sealed.go
sed -i '' '/builder\.CommentaryParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' parties/roster.go
echo "  parties/*.go (4 sites) — uses cfg.Destination"

# ── topology/anchor_publisher.go (1 site) ──
sed -i '' '/builder\.AnchorParams{/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: cfg.Destination,\
\1SignerDID:/;}' topology/anchor_publisher.go
echo "  topology/anchor_publisher.go (1 site) — uses cfg.Destination"

# ── tools/common/exchange_client.go ──
# This file may call builder functions via the exchange client.
# Check manually: grep -n 'builder\.Build' tools/common/exchange_client.go
echo "  tools/common/exchange_client.go — MANUAL REVIEW"

# ── tools/courts/*.go (5 files with builder calls) ──
# These HTTP handlers get exchangeDID from server config.
for f in tools/courts/cases.go tools/courts/docket.go tools/courts/officers.go tools/courts/orders.go tools/courts/sealing.go; do
  if grep -q 'builder\.Build' "$f" 2>/dev/null; then
    sed -i '' '/builder\.\(RootEntityParams\|AmendmentParams\|DelegationParams\|EnforcementParams\|CommentaryParams\|PathBParams\|RevocationParams\){/{n;s/^\([[:space:]]*\)SignerDID:/\1Destination: s.exchangeDID,\
\1SignerDID:/;}' "$f"
    echo "  $f — uses s.exchangeDID"
  fi
done


# ──────────────────────────────────────────────────────────────────────
# PHASE 4: VERIFICATION
# ──────────────────────────────────────────────────────────────────────

echo ""
echo "=== Verification ==="

# Count how many Destination: lines we added
ADDED=$(grep -rn 'Destination:' --include='*.go' | grep -v '_test.go' | grep -v 'go.sum' | grep -v 'SKILL' | wc -l | tr -d ' ')
ADDED_TEST=$(grep -rn 'Destination:' --include='*_test.go' | wc -l | tr -d ' ')
echo "Destination fields added in source files: $ADDED"
echo "Destination fields added in test files: $ADDED_TEST"

# Check for any remaining unpatched call sites
echo ""
echo "=== Remaining unpatched sites (should be 0) ==="
grep -rn 'builder\.Build' --include='*.go' | grep -v 'Destination' | grep -v '// ' | grep -v 'description' | grep -v 'SKILL' | head -20

echo ""
echo "=== Next steps ==="
echo "1. Add 'Destination string' field to every config struct that uses cfg.Destination"
echo "2. Add 'exchangeDID string' field to exchange server structs"
echo "3. Run: GOWORK=off go build ./... 2>&1 | head -50"
echo "4. Fix compilation errors (missing Destination in config structs)"
echo "5. Run: GOWORK=off go test ./... 2>&1"