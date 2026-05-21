#!/usr/bin/env bash
# scripts/run-jn.sh — run the JN auditor (network-api). Docker by DEFAULT
# (like the rest of the stack); --native is the no-docker fallback.
#
# Fully ENV-DRIVEN: network-api reads its whole config from env, so the SAME
# binary runs native / docker-compose / k8s — only the injected env + mounted
# file paths differ. No DID, no path is baked into the Go.
#
# The JN's Smart-Edge daemon: verifies the ledger's cosigned tree heads, owns
# the durable gossip store, and (with a bootstrap present) becomes an ACTIVE
# auditor — equivocation scanner + gossip ingest + the bootstrap-derived
# witness set. Inputs:
#
#   mTLS material   identity infra (make identity)   → API_AUTH_* (Secret mount)
#   gossip store    make infra-up (docker default)   → API_GOSSIP_STORE_DSN
#   the ledger      the running ledger               → API_LEDGER_ENDPOINT (REQUIRED, probed at boot)
#   trust root      witness fleet's bootstrap        → API_NETWORK_BOOTSTRAP_FILE
#     (falls back to LEDGER_NETWORK_BOOTSTRAP_FILE, the var the witness emits)
#   quorum K        witness fleet                    → API_WITNESS_QUORUM_K (from LEDGER_WITNESS_QUORUM_K)
#
# With a bootstrap set, the witness set + gossip peer DERIVE from it (the JN
# never hand-lists witness DIDs). Without one, the JN runs as a passive
# auditor. The artifact store is left OUT (ledger-only).
#
# Usage:
#   ./scripts/run-jn.sh up            # docker (default)
#   ./scripts/run-jn.sh up --native   # no-docker fallback
#   ./scripts/run-jn.sh down [--native]
#   JN_BACKEND=native ./scripts/run-jn.sh
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
BIN="${REPO_ROOT}/bin/network-api"

BACKEND="${JN_BACKEND:-docker}"
SUBCMD="up"
for arg in "$@"; do
    case "${arg}" in
        up|down) SUBCMD="${arg}" ;;
        --docker) BACKEND="docker" ;;
        --native) BACKEND="native" ;;
        -h|--help) sed -n '1,/^set -euo pipefail/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "FATAL: unknown argument: ${arg} (use --help)" >&2; exit 2 ;;
    esac
done

if [ "${SUBCMD}" = "down" ]; then
    if [ "${BACKEND}" = "native" ]; then
        pkill -f 'bin/network-api' 2>/dev/null && echo "native network-api stopped" || echo "no native network-api running"
    else
        docker compose -f "${COMPOSE}" down
    fi
    exit 0
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
    [ -x "${BIN%/network-api}/judicial-cli" ] || make judicial-cli >/dev/null
    "${REPO_ROOT}/bin/judicial-cli" keygen --method key --out "${AUD}/jn.key.json" >/dev/null
    HEX="$(grep -o '"private_key_hex"[^,]*' "${AUD}/jn.key.json" | sed 's/.*"\([0-9a-f]*\)"$/\1/')"
    command -v python3 >/dev/null 2>&1 || { echo "FATAL: python3 needed to encode the gossip key PEM locally (prod mounts a Secret instead)" >&2; exit 1; }
    python3 -c "import base64,sys; b=bytes.fromhex(sys.argv[1]); open(sys.argv[2],'w').write('-----BEGIN ATTESTA SECP256K1 PRIVATE KEY-----\n'+base64.encodebytes(b).decode()+'-----END ATTESTA SECP256K1 PRIVATE KEY-----\n')" "${HEX}" "${AUD}/gossip.pem"
fi

# 3. Durable gossip store (docker default). Honor an operator-set DSN.
if [ -z "${API_GOSSIP_STORE_DSN:-}" ]; then
    make infra-up >/dev/null
    export "$(make -s infra-dsn)"
fi

# 4. Shared trust root → ACTIVE auditor. API_* explicit; else the LEDGER_* var
#    the witness fleet emits. Quorum K from the witness fleet's emit.
BOOT="${API_NETWORK_BOOTSTRAP_FILE:-${LEDGER_NETWORK_BOOTSTRAP_FILE:-}}"
K="${API_WITNESS_QUORUM_K:-${LEDGER_WITNESS_QUORUM_K:-5}}"

# ── Docker backend (default) ─────────────────────────────────────────
if [ "${BACKEND}" = "docker" ]; then
    if [ -z "${BOOT}" ]; then
        echo "FATAL: docker run needs a bootstrap file to mount." >&2
        echo "       export LEDGER_NETWORK_BOOTSTRAP_FILE=<abs path>, or run passively with --native." >&2
        exit 1
    fi
    export JN_BOOTSTRAP_FILE="${BOOT}" JN_WITNESS_QUORUM_K="${K}"
    echo "== network-api (docker · ACTIVE auditor) =="
    echo "  bootstrap : ${BOOT}  (mounted ro)   quorum_k: ${K}"
    echo "  ledger    : http://host.docker.internal:8080 (REQUIRED — probed at boot)"
    echo "  health    : curl --cacert ${CERTS}/ca.crt --cert ${CERTS}/judge-adams.client.crt --key ${CERTS}/judge-adams.client.key https://localhost:8443/healthz"
    exec docker compose -f "${COMPOSE}" up --build
fi

# ── Native backend (no-docker fallback) ──────────────────────────────
export API_LEDGER_ENDPOINT="${API_LEDGER_ENDPOINT:-http://localhost:8080}"
export API_AUTH_CLIENT_CA_FILE="${CERTS}/ca.crt"
export API_AUTH_TLS_CERT_FILE="${CERTS}/server.crt"
export API_AUTH_TLS_KEY_FILE="${CERTS}/server.key"
if [ -n "${BOOT}" ]; then
    export API_NETWORK_BOOTSTRAP_FILE="${BOOT}"
    export API_EQUIVOCATION_SCANNER_ENABLED=true
    export API_EQUIVOCATION_SCANNER_SIGNING_KEY_FILE="${AUD}/gossip.pem"
    export API_GOSSIP_INGEST_ENABLED=true
    export API_GOSSIP_FEED_ENABLED=true
    export API_WITNESS_QUORUM_K="${K}"
    MODE="ACTIVE (scanner + gossip ingest + K=${K} witness set, derived from bootstrap)"
else
    MODE="passive (no bootstrap; export LEDGER_NETWORK_BOOTSTRAP_FILE to activate)"
fi
[ -x "${BIN}" ] || make network-api
echo "== network-api (native) — ${MODE} =="
echo "  ledger    : ${API_LEDGER_ENDPOINT}  (REQUIRED — probed at boot)"
echo "  gossip    : ${API_GOSSIP_STORE_DSN}"
echo "  bootstrap : ${BOOT:-<none>}"
echo "  health    : curl --cacert ${CERTS}/ca.crt --cert ${CERTS}/judge-adams.client.crt --key ${CERTS}/judge-adams.client.key https://localhost:8443/healthz"
echo ""
exec "${BIN}"
