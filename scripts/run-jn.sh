#!/usr/bin/env bash
# scripts/run-jn.sh — run the JN auditor (network-api) against a local stack.
#
# The JN's Smart-Edge daemon: it verifies the ledger's cosigned tree heads,
# owns the durable gossip store, and (once the auditor features are switched
# on) scans peers for equivocation. This is the JN counterpart to the
# ledger/witness run-local.sh — it wires the daemon's inputs PURELY via a
# generated config + env, no DID ever in JSON:
#
#   mTLS material      identity infra (make identity)      → config auth.*
#   gossip store DSN   make infra-up                       → API_GOSSIP_STORE_DSN
#   the ledger         the running ledger                  → API_LEDGER_ENDPOINT
#   trust root         the witness fleet's bootstrap       → API_NETWORK_BOOTSTRAP_FILE
#     (falls back to LEDGER_NETWORK_BOOTSTRAP_FILE, the var the witness emits)
#
# The generated config's cert paths are REPO_ROOT-absolute, so it is
# machine-agnostic (nothing about your home dir is baked in).
#
# Usage:
#   ./scripts/run-jn.sh up           # ensure deps, generate config, run network-api
#   ./scripts/run-jn.sh              # same as up
#   API_LEDGER_ENDPOINT=http://localhost:8080 ./scripts/run-jn.sh
#
# Zero-trust: mTLS is REQUIRED (no no-auth path). Call it with a client cert:
#   curl --cacert .run/certs/ca.crt \
#        --cert .run/certs/judge-adams.client.crt \
#        --key  .run/certs/judge-adams.client.key https://localhost:8443/healthz
#
# Make it an active auditor (phase 2) by setting, in the generated config:
#   "equivocation_scanner": {"enabled": true, "signing_key_file": "..."}
#   "gossip_ingest":        {"enabled": true, "peers": [...]}
#   "witness": {"sets": [{"log_did": "...", "witness_dids": [...], "quorum_k": K}]}
# all three then REQUIRE the bootstrap (cross-log keysets need the NetworkID).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"
CERTS="${REPO_ROOT}/.run/certs"
RUN="${REPO_ROOT}/.run"
BIN="${REPO_ROOT}/bin/network-api"
CONFIG="${RUN}/network-api.config.json"

case "${1:-up}" in
    up) ;;
    -h|--help) sed -n '1,/^set -euo pipefail/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "FATAL: unknown argument: ${1} (use --help)" >&2; exit 2 ;;
esac

# 1. Identity infra (mTLS material). Mint if absent — make identity is idempotent.
if [ ! -s "${CERTS}/ca.crt" ] || [ ! -s "${CERTS}/server.crt" ] || [ ! -s "${CERTS}/server.key" ]; then
    echo "== minting identity infra (make identity) =="
    make identity
fi

# 2. Durable gossip store. Honor an operator-set DSN; otherwise bring up the
#    local infra (idempotent) and read its DSN.
if [ -z "${API_GOSSIP_STORE_DSN:-}" ]; then
    make infra-up
    export "$(make -s infra-dsn)"
fi

# 3. Shared trust root (network bootstrap → NetworkID). API_* explicit; else the
#    LEDGER_* var the witness fleet emits. Optional until an auditor feature is on.
if [ -z "${API_NETWORK_BOOTSTRAP_FILE:-}" ] && [ -n "${LEDGER_NETWORK_BOOTSTRAP_FILE:-}" ]; then
    export API_NETWORK_BOOTSTRAP_FILE="${LEDGER_NETWORK_BOOTSTRAP_FILE}"
fi

# 4. The ledger the auditor verifies (default: the local SeaweedFS ledger).
export API_LEDGER_ENDPOINT="${API_LEDGER_ENDPOINT:-http://localhost:8080}"

# 5. Generate the config — cert paths REPO_ROOT-absolute (machine-agnostic).
mkdir -p "${RUN}"
cat > "${CONFIG}" <<JSON
{
  "listen_addr": "${JN_LISTEN_ADDR:-:8443}",
  "ledger_endpoint": "${API_LEDGER_ENDPOINT}",
  "artifact_store_endpoint": "${JN_ARTIFACT_STORE_ENDPOINT:-}",
  "verification_endpoint": "${JN_VERIFICATION_ENDPOINT:-http://localhost:8080}",
  "keystore": { "backend": "memory" },
  "nonce_store": { "backend": "memory" },
  "auth": {
    "mode": "mtls",
    "client_ca_file": "${CERTS}/ca.crt",
    "tls_cert_file": "${CERTS}/server.crt",
    "tls_key_file": "${CERTS}/server.key"
  }
}
JSON

# 6. Build + run.
[ -x "${BIN}" ] || make network-api
echo "== starting network-api =="
echo "  listen    : ${JN_LISTEN_ADDR:-:8443}  (mTLS — client cert REQUIRED; zero-trust)"
echo "  ledger    : ${API_LEDGER_ENDPOINT}  (REQUIRED — probed at boot; the JN won't start without it)"
echo "  artifact  : out (ledger-only deployment)"
echo "  gossip    : ${API_GOSSIP_STORE_DSN}"
echo "  bootstrap : ${API_NETWORK_BOOTSTRAP_FILE:-<none — export LEDGER_NETWORK_BOOTSTRAP_FILE to enable cosign verification>}"
echo "  config    : ${CONFIG}"
echo "  health    : curl --cacert ${CERTS}/ca.crt --cert ${CERTS}/judge-adams.client.crt --key ${CERTS}/judge-adams.client.key https://localhost${JN_LISTEN_ADDR:-:8443}/healthz"
echo ""
exec "${BIN}" -config "${CONFIG}"
