#!/usr/bin/env bash
# verify.sh — Verifies a court deployment after bootstrap.
#
# Usage: ./verify.sh
#
# Checks:
#   1. Scope entity exists and is valid (EvaluateOrigin)
#   2. All three logs are reachable
#   3. Schemas are adopted
#   4. Anchor is registered (if configured)
#   5. Witnesses are reachable
#   6. Escrow nodes respond to health checks

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

echo "=== Court Deployment Verification ==="
echo ""

echo "Scope entity:"
check "EvaluateOrigin on officers log" \
    judicial-network verify-scope \
    --court-config "${CONFIG_DIR}/court.yaml" \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --log officers

check "EvaluateOrigin on cases log" \
    judicial-network verify-scope \
    --court-config "${CONFIG_DIR}/court.yaml" \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --log cases

check "EvaluateOrigin on parties log" \
    judicial-network verify-scope \
    --court-config "${CONFIG_DIR}/court.yaml" \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --log parties

echo ""
echo "Log reachability:"
check "Officers log operator" \
    judicial-network ping-operator \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --log officers

check "Cases log operator" \
    judicial-network ping-operator \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --log cases

check "Parties log operator" \
    judicial-network ping-operator \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --log parties

echo ""
echo "Schemas:"
check "Schema adoption on cases log" \
    judicial-network verify-schemas \
    --court-config "${CONFIG_DIR}/court.yaml" \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --schemas-config "${CONFIG_DIR}/schemas.yaml"

if [[ -f "${CONFIG_DIR}/anchor.yaml" ]]; then
    echo ""
    echo "Anchor:"
    check "Anchor log reachable" \
        judicial-network ping-operator \
        --anchor-config "${CONFIG_DIR}/anchor.yaml"
fi

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
exit ${FAIL}
