#!/usr/bin/env bash
# verify.sh — Verifies Davidson County Court deployment.
#
# Usage: ./verify.sh
#
# Davidson-specific: also checks division entities, Davidson-specific
# schemas, and anchor connectivity to TN state log.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config"

PASS=0
FAIL=0

check() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  ✓ ${name}"
        PASS=$((PASS + 1))
    else
        echo "  ✗ ${name}"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Davidson County Deployment Verification ==="
echo ""

echo "Scope entities:"
for log in officers cases parties; do
    check "EvaluateOrigin on ${log} log" \
        judicial-network verify-scope \
        --court-config "${CONFIG_DIR}/court.yaml" \
        --logs-config "${CONFIG_DIR}/logs.yaml" \
        --log "${log}"
done

echo ""
echo "Log reachability:"
for log in officers cases parties; do
    check "${log} log operator" \
        judicial-network ping-operator \
        --logs-config "${CONFIG_DIR}/logs.yaml" \
        --log "${log}"
done

echo ""
echo "Anchor:"
check "TN state anchor reachable" \
    judicial-network ping-operator \
    --anchor-config "${CONFIG_DIR}/anchor.yaml"

check "Anchor entry published" \
    judicial-network verify-anchor \
    --court-config "${CONFIG_DIR}/court.yaml" \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --anchor-config "${CONFIG_DIR}/anchor.yaml"

echo ""
echo "Schemas:"
check "Statewide schemas adopted" \
    judicial-network verify-schemas \
    --court-config "${CONFIG_DIR}/court.yaml" \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --schemas-config "${CONFIG_DIR}/schemas.yaml"

echo ""
echo "Divisions:"
for division in criminal civil chancery circuit general-sessions juvenile; do
    check "Division entity: ${division}" \
        judicial-network verify-division \
        --court-config "${CONFIG_DIR}/court.yaml" \
        --logs-config "${CONFIG_DIR}/logs.yaml" \
        --division "${division}"
done

echo ""
echo "Witnesses:"
check "Witness quorum reachable (3-of-4)" \
    judicial-network verify-witnesses \
    --witnesses-config "${CONFIG_DIR}/witnesses.yaml"

echo ""
echo "Escrow:"
check "Escrow threshold reachable (3-of-5)" \
    judicial-network verify-escrow \
    --escrow-config "${CONFIG_DIR}/escrow.yaml"

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
exit ${FAIL}
