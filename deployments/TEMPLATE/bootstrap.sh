#!/usr/bin/env bash
# bootstrap.sh — Provisions a new court from configuration files.
#
# Usage: ./bootstrap.sh [--dry-run]
#
# Reads config/ YAML files and calls the judicial-network CLI to:
#   1. Provision three logs (officers, cases, parties)
#   2. Register initial officers
#   3. Adopt schemas
#   4. Register anchor
#   5. Verify the scope entity
#
# Prerequisites:
#   - judicial-network CLI built and on PATH
#   - Exchange credentials configured
#   - Operator endpoints reachable

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config"

DRY_RUN=""
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN="--dry-run"
    echo "[DRY RUN] No entries will be submitted."
fi

echo "=== Court Bootstrap ==="
echo "Config directory: ${CONFIG_DIR}"
echo ""

# Validate required config files exist.
for f in court.yaml logs.yaml exchange.yaml storage.yaml schemas.yaml witnesses.yaml escrow.yaml; do
    if [[ ! -f "${CONFIG_DIR}/${f}" ]]; then
        echo "ERROR: Missing required config file: ${CONFIG_DIR}/${f}"
        exit 1
    fi
done

echo "Step 1: Provisioning three logs..."
judicial-network provision \
    --court-config "${CONFIG_DIR}/court.yaml" \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --exchange-config "${CONFIG_DIR}/exchange.yaml" \
    --escrow-config "${CONFIG_DIR}/escrow.yaml" \
    ${DRY_RUN}

echo "Step 2: Adopting schemas..."
judicial-network schema-adopt \
    --court-config "${CONFIG_DIR}/court.yaml" \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --schemas-config "${CONFIG_DIR}/schemas.yaml" \
    ${DRY_RUN}

echo "Step 3: Registering anchor..."
if [[ -f "${CONFIG_DIR}/anchor.yaml" ]]; then
    judicial-network anchor-register \
        --court-config "${CONFIG_DIR}/court.yaml" \
        --logs-config "${CONFIG_DIR}/logs.yaml" \
        --anchor-config "${CONFIG_DIR}/anchor.yaml" \
        ${DRY_RUN}
else
    echo "  (No anchor.yaml — operating standalone)"
fi

echo "Step 4: Configuring witnesses..."
judicial-network witness-configure \
    --court-config "${CONFIG_DIR}/court.yaml" \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --witnesses-config "${CONFIG_DIR}/witnesses.yaml" \
    ${DRY_RUN}

echo ""
echo "=== Bootstrap complete ==="
echo "Run verify.sh to confirm the deployment."
