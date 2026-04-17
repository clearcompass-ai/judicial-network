#!/usr/bin/env bash
# bootstrap.sh — Provisions Davidson County Court.
#
# Usage: ./bootstrap.sh [--dry-run]
#
# Davidson-specific: bootstraps initial officers for all six divisions
# after the standard three-log provisioning.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config"

DRY_RUN=""
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN="--dry-run"
    echo "[DRY RUN] No entries will be submitted."
fi

echo "=== Davidson County Court Bootstrap ==="
echo "Court: did:web:courts.nashville.gov"
echo "Config: ${CONFIG_DIR}"
echo ""

# Validate required config files.
for f in court.yaml logs.yaml exchange.yaml storage.yaml schemas.yaml witnesses.yaml escrow.yaml; do
    if [[ ! -f "${CONFIG_DIR}/${f}" ]]; then
        echo "ERROR: Missing config: ${CONFIG_DIR}/${f}"
        exit 1
    fi
done

echo "Phase 1: Provisioning three logs..."
judicial-network provision \
    --court-config "${CONFIG_DIR}/court.yaml" \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --exchange-config "${CONFIG_DIR}/exchange.yaml" \
    --escrow-config "${CONFIG_DIR}/escrow.yaml" \
    ${DRY_RUN}

echo "Phase 2: Adopting schemas (statewide + Davidson-specific)..."
judicial-network schema-adopt \
    --court-config "${CONFIG_DIR}/court.yaml" \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --schemas-config "${CONFIG_DIR}/schemas.yaml" \
    ${DRY_RUN}

echo "Phase 3: Registering TN state anchor..."
judicial-network anchor-register \
    --court-config "${CONFIG_DIR}/court.yaml" \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --anchor-config "${CONFIG_DIR}/anchor.yaml" \
    ${DRY_RUN}

echo "Phase 4: Configuring witnesses (3-of-4)..."
judicial-network witness-configure \
    --court-config "${CONFIG_DIR}/court.yaml" \
    --logs-config "${CONFIG_DIR}/logs.yaml" \
    --witnesses-config "${CONFIG_DIR}/witnesses.yaml" \
    ${DRY_RUN}

echo "Phase 5: Bootstrapping Davidson County divisions..."
for division in criminal civil chancery circuit general-sessions juvenile; do
    echo "  Creating division: ${division}"
    judicial-network create-division \
        --court-config "${CONFIG_DIR}/court.yaml" \
        --logs-config "${CONFIG_DIR}/logs.yaml" \
        --division "${division}" \
        ${DRY_RUN}
done

echo ""
echo "=== Davidson County bootstrap complete ==="
echo "Next steps:"
echo "  1. Run ./verify.sh to confirm deployment"
echo "  2. Bootstrap initial officers via officer-bootstrap"
echo "  3. Start daily docket generation"
