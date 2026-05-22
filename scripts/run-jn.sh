#!/usr/bin/env bash
# scripts/run-jn.sh — run the JN enforcer (network-api) in Docker. DOCKER ONLY.
#
# Fully ENV-DRIVEN: network-api reads its whole config from env, so the SAME
# image runs here (docker-compose) or in k8s — only the injected env + mounted
# file paths differ. No DID, no path is baked into the Go.
#
# The JN's Smart-Edge daemon is the ENFORCER (Separation of Duties): it verifies
# the ledger's cosigned tree heads, admits/enforces on the commit clock, and runs
# a VERIFY-ONLY gossip ingest — it PULLS the external auditor's curated /v1/gossip
# feed and re-verifies every event against JN-local trust. It hosts NO custody:
# no gossip store, no served feed, no equivocation scanner. Custody + detection
# live in the external auditor service (deployment/local/docker-compose.auditor.yml).
# Inputs:
#
#   mTLS material   identity infra (make identity)   → mounted Secret → API_AUTH_*
#   the ledger      the running ledger               → API_LEDGER_ENDPOINT (REQUIRED, probed at boot)
#   the auditor     the running auditor's feed        → API_GOSSIP_INGEST_PEER_URL (verify-only source)
#   trust root      witness fleet's bootstrap        → API_NETWORK_BOOTSTRAP_FILE
#     (falls back to LEDGER_NETWORK_BOOTSTRAP_FILE, the var the witness emits)
#   quorum K        witness fleet                    → API_WITNESS_QUORUM_K (from LEDGER_WITNESS_QUORUM_K)
#
# The witness set + ingest peer DERIVE from the bootstrap (the JN never
# hand-lists witness DIDs). The artifact store is left OUT (ledger-only).
#
# Usage:
#   ./scripts/run-jn.sh up      # build + run the container (foreground)
#   ./scripts/run-jn.sh down    # docker compose down
#
# Zero-trust: mTLS REQUIRED. Health check (any actor's client cert):
#   curl --cacert .run/certs/ca.crt --cert .run/certs/judge-adams.client.crt \
#        --key .run/certs/judge-adams.client.key https://localhost:8443/healthz
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"
CERTS="${REPO_ROOT}/.run/certs"
COMPOSE="${REPO_ROOT}/deployment/local/docker-compose.jn.yml"
IMAGE="${JN_IMAGE:-ghcr.io/clearcompass-ai/judicial-network:${JN_IMAGE_TAG:-dev}}"
export JN_IMAGE="${IMAGE}" # the compose references the SAME ref

SUBCMD="up"
for arg in "$@"; do
    case "${arg}" in
        up|down) SUBCMD="${arg}" ;;
        -h|--help) sed -n '1,/^set -euo pipefail/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "FATAL: unknown argument: ${arg} (use --help)" >&2; exit 2 ;;
    esac
done

if [ "${SUBCMD}" = "down" ]; then
    docker compose -f "${COMPOSE}" down
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "FATAL: docker daemon not reachable. The JN enforcer runs in Docker only." >&2
    exit 1
fi

# 1. Identity infra (mTLS material). Mint if absent — make identity is idempotent.
if [ ! -s "${CERTS}/ca.crt" ] || [ ! -s "${CERTS}/server.crt" ] || [ ! -s "${CERTS}/server.key" ]; then
    echo "== minting identity infra (make identity) =="
    make identity
fi

# 2. Shared trust root → witness sets for verify-only ingest. API_* explicit;
#    else the LEDGER_* var the witness fleet emits. Quorum K from the fleet.
BOOT="${API_NETWORK_BOOTSTRAP_FILE:-${LEDGER_NETWORK_BOOTSTRAP_FILE:-}}"
K="${API_WITNESS_QUORUM_K:-${LEDGER_WITNESS_QUORUM_K:-5}}"
if [ -z "${BOOT}" ]; then
    echo "FATAL: no bootstrap to mount. Export LEDGER_NETWORK_BOOTSTRAP_FILE=<abs path>" >&2
    echo "       (the standalone-witness fleet emits it via 'make -s print-env')." >&2
    exit 1
fi

# 3. Provision the image. Strict-pull (JN_IMAGE_PULL=1, the e2e default) pulls
#    the published image; otherwise build locally for JN dev, injecting the
#    egress proxy CA when present so fetches verify behind a TLS-inspecting proxy.
if [ "${JN_IMAGE_PULL:-0}" = "1" ]; then
    echo "== pulling network-api image (${IMAGE}) =="
    docker pull "${IMAGE}"
else
    CA_BUNDLE="${JN_CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}"
    BUILD_SECRET=()
    [ -s "${CA_BUNDLE}" ] && BUILD_SECRET=(--secret "id=ca_bundle,src=${CA_BUNDLE}")
    echo "== building network-api image (${IMAGE}) =="
    DOCKER_BUILDKIT=1 docker build -f deployment/local/Dockerfile.network-api \
        "${BUILD_SECRET[@]}" \
        --build-arg VERSION="$(git -C "${REPO_ROOT}" describe --tags --always 2>/dev/null || echo dev)" \
        -t "${IMAGE}" "${REPO_ROOT}"
fi

# In-container, the ledger + auditor are host.docker.internal (compose defaults).
# Drop any localhost endpoints from this shell so a leftover export can't leak in.
unset API_LEDGER_ENDPOINT
export JN_BOOTSTRAP_FILE="${BOOT}" JN_WITNESS_QUORUM_K="${K}"
# The verify-only ingest source: the external auditor's /v1/gossip (override to
# point elsewhere). The auditor runs separately (docker-compose.auditor.yml).
export API_GOSSIP_INGEST_PEER_URL="${API_GOSSIP_INGEST_PEER_URL:-http://host.docker.internal:8088}"

echo "== network-api (docker · ENFORCER · verify-only ingest) =="
echo "  bootstrap : ${BOOT}  (mounted ro)   quorum_k: ${K}"
echo "  ledger    : http://host.docker.internal:8080 (REQUIRED — probed at boot)"
echo "  auditor   : ${API_GOSSIP_INGEST_PEER_URL} (verify-only /v1/gossip source)"
echo "  health    : curl --cacert ${CERTS}/ca.crt --cert ${CERTS}/judge-adams.client.crt --key ${CERTS}/judge-adams.client.key https://localhost:8443/healthz"
echo ""
exec docker compose -f "${COMPOSE}" up