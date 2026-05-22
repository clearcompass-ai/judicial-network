#!/usr/bin/env bash
# scripts/run-jn.sh — run the JN auditor (network-api) in Docker. DOCKER ONLY.
#
# Fully ENV-DRIVEN: network-api reads its whole config from env, so the SAME
# image runs here (docker-compose) or in k8s — only the injected env + mounted
# file paths differ. No DID, no path is baked into the Go.
#
# The JN's Smart-Edge daemon: verifies the ledger's cosigned tree heads, owns
# the durable gossip store, and (with a bootstrap present) is an ACTIVE auditor
# — equivocation scanner + gossip ingest + the bootstrap-derived witness set.
# Inputs:
#
#   mTLS material   identity infra (make identity)   → mounted Secret → API_AUTH_*
#   gossip store    make infra-up (docker)           → API_GOSSIP_STORE_DSN
#   the ledger      the running ledger               → API_LEDGER_ENDPOINT (REQUIRED, probed at boot)
#   trust root      witness fleet's bootstrap        → API_NETWORK_BOOTSTRAP_FILE
#     (falls back to LEDGER_NETWORK_BOOTSTRAP_FILE, the var the witness emits)
#   quorum K        witness fleet                    → API_WITNESS_QUORUM_K (from LEDGER_WITNESS_QUORUM_K)
#
# The witness set + gossip peer DERIVE from the bootstrap (the JN never
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
AUD="${REPO_ROOT}/.run/auditor"
COMPOSE="${REPO_ROOT}/deployment/local/docker-compose.jn.yml"

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
    echo "FATAL: docker daemon not reachable. The JN auditor runs in Docker only." >&2
    exit 1
fi

# 1. Identity infra (mTLS material). Mint if absent — make identity is idempotent.
if [ ! -s "${CERTS}/ca.crt" ] || [ ! -s "${CERTS}/server.crt" ] || [ ! -s "${CERTS}/server.key" ]; then
    echo "== minting identity infra (make identity) =="
    make identity
fi

# 2. The JN's gossip signing key (the auditor's self-certifying did:key
#    identity). Minted ONCE; in prod this is a mounted Secret, never generated
#    on the box. PEM = "ATTESTA SECP256K1 PRIVATE KEY" (raw 32-byte scalar).
mkdir -p "${AUD}"
if [ ! -s "${AUD}/gossip.pem" ]; then
    echo "== minting JN gossip signing key (auditor identity) =="
    [ -x "${REPO_ROOT}/bin/judicial-cli" ] || make judicial-cli >/dev/null
    "${REPO_ROOT}/bin/judicial-cli" keygen --method key --out "${AUD}/jn.key.json" >/dev/null
    HEX="$(grep -o '"private_key_hex"[^,]*' "${AUD}/jn.key.json" | sed 's/.*"\([0-9a-f]*\)"$/\1/')"
    command -v python3 >/dev/null 2>&1 || { echo "FATAL: python3 needed to encode the gossip key PEM locally (prod mounts a Secret instead)" >&2; exit 1; }
    python3 -c "import base64,sys; b=bytes.fromhex(sys.argv[1]); open(sys.argv[2],'w').write('-----BEGIN ATTESTA SECP256K1 PRIVATE KEY-----\n'+base64.encodebytes(b).decode()+'-----END ATTESTA SECP256K1 PRIVATE KEY-----\n')" "${HEX}" "${AUD}/gossip.pem"
fi

# 3. Durable gossip store (docker). The CONTAINER reaches it via
#    host.docker.internal (compose default) — so we do NOT export a localhost
#    DSN that would leak into the container.
make infra-up >/dev/null

# 4. Shared trust root → ACTIVE auditor. API_* explicit; else the LEDGER_* var
#    the witness fleet emits. Quorum K from the witness fleet's emit.
BOOT="${API_NETWORK_BOOTSTRAP_FILE:-${LEDGER_NETWORK_BOOTSTRAP_FILE:-}}"
K="${API_WITNESS_QUORUM_K:-${LEDGER_WITNESS_QUORUM_K:-5}}"
if [ -z "${BOOT}" ]; then
    echo "FATAL: no bootstrap to mount. Export LEDGER_NETWORK_BOOTSTRAP_FILE=<abs path>" >&2
    echo "       (the standalone-witness fleet emits it via 'make -s print-env')." >&2
    exit 1
fi

# In-container, the ledger + gossip PG are host.docker.internal (compose
# defaults). Drop any localhost values from this shell so a leftover export
# can't leak into the container.
unset API_LEDGER_ENDPOINT API_GOSSIP_STORE_DSN
export JN_BOOTSTRAP_FILE="${BOOT}" JN_WITNESS_QUORUM_K="${K}"

echo "== network-api (docker · ACTIVE auditor) =="
echo "  bootstrap : ${BOOT}  (mounted ro)   quorum_k: ${K}"
echo "  ledger    : http://host.docker.internal:8080 (REQUIRED — probed at boot)"
echo "  gossip    : host.docker.internal:5433 (durable Postgres)"
echo "  health    : curl --cacert ${CERTS}/ca.crt --cert ${CERTS}/judge-adams.client.crt --key ${CERTS}/judge-adams.client.key https://localhost:8443/healthz"
echo ""
exec docker compose -f "${COMPOSE}" up --build
