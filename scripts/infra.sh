#!/usr/bin/env bash
# scripts/infra.sh — the single authoritative launcher for JN local infra.
#
# Infra = the Postgres instance backing the durable gossip store
# (peer_gossip / GossipStore.PostgresDSN). This script launches NOTHING
# else (no Go build, no app); run network-api separately, pointed at the
# DSN this script prints (config-from-env, the same way the ledger takes
# its inputs).
#
# Backend — DOCKER BY DEFAULT; native is the optional no-docker fallback:
#   docker  (default) docker compose (deployment/local/docker-compose.gossip-db.yml)
#   native  (--native / INFRA_BACKEND=native) a local Postgres via
#           initdb/pg_ctl under .run/ — no Docker daemon required.
#
# Usage:
#   ./scripts/infra.sh up                 # docker (default)
#   ./scripts/infra.sh up --native        # no-docker fallback
#   ./scripts/infra.sh {down|destroy|status} [--native]
#   ./scripts/infra.sh dsn                # print API_GOSSIP_STORE_DSN
#
# Env (defaults shown) — shared by both backends:
#   JN_GOSSIP_PG_USER (attesta)   JN_GOSSIP_PG_PASS (attestapassword)
#   JN_GOSSIP_PG_DB   (jn_gossip) JN_GOSSIP_PG_PORT (5433)
#   INFRA_BACKEND     (docker|native)  — same as --docker/--native

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deployment/local/docker-compose.gossip-db.yml"
RUN_DIR="${REPO_ROOT}/.run/gossip-db"
PGDATA="${RUN_DIR}/data"

PG_USER="${JN_GOSSIP_PG_USER:-attesta}"
PG_PASS="${JN_GOSSIP_PG_PASS:-attestapassword}"
PG_DB="${JN_GOSSIP_PG_DB:-jn_gossip}"
PG_PORT="${JN_GOSSIP_PG_PORT:-5433}"

BACKEND="${INFRA_BACKEND:-docker}"
SUBCMD=""
for arg in "$@"; do
    case "${arg}" in
        --native) BACKEND="native" ;;
        --docker) BACKEND="docker" ;;
        up|down|destroy|status|dsn) SUBCMD="${arg}" ;;
        -h|--help) sed -n '1,/^set -euo pipefail/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "FATAL: unknown argument: ${arg} (use --help)" >&2; exit 2 ;;
    esac
done
SUBCMD="${SUBCMD:-up}"

dsn() { echo "API_GOSSIP_STORE_DSN=postgres://${PG_USER}:${PG_PASS}@localhost:${PG_PORT}/${PG_DB}?sslmode=disable"; }

summary() {
    cat <<EOF

== JN gossip store Postgres UP (${1}) ==
  host port : ${PG_PORT}    database : ${PG_DB}

Run network-api against it (config-from-env, like the ledger):
  export "$(dsn)"
  ./bin/network-api -config <config.json>

The peer_gossip table is created at boot (PostgresStore.Migrate).
Tear down: ./scripts/infra.sh down${2}
EOF
}

# ── docker backend (default) ─────────────────────────────────────
docker_compose() { docker compose -f "${COMPOSE_FILE}" "$@"; }

up_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "FATAL: docker not on PATH. Optional fallback: ./scripts/infra.sh up --native" >&2
        exit 1
    fi
    echo "== infra up (docker) =="
    if ! docker_compose up -d; then
        echo "ERROR: 'docker compose up' failed — is the docker daemon running?" >&2
        echo "       Optional no-docker fallback: ./scripts/infra.sh up --native" >&2
        exit 1
    fi
    for _ in $(seq 1 30); do
        docker_compose exec -T gossip-db pg_isready -U "${PG_USER}" -d "${PG_DB}" >/dev/null 2>&1 && break
        sleep 1
    done
    summary "docker · container jn-gossip-db"
}

# ── native backend (optional, no docker) ─────────────────────────
find_pgbin() {
    if command -v initdb >/dev/null 2>&1 && command -v pg_ctl >/dev/null 2>&1; then
        dirname "$(command -v initdb)"; return 0
    fi
    for d in /usr/lib/postgresql/*/bin /usr/pgsql-*/bin /opt/homebrew/opt/postgresql*/bin; do
        [ -x "${d}/initdb" ] && [ -x "${d}/pg_ctl" ] && { echo "${d}"; return 0; }
    done
    return 1
}

# Run a pg binary; drop to the 'postgres' user when invoked as root
# (initdb/pg_ctl refuse to run as root).
pg_run() {
    if [ "$(id -u)" = "0" ]; then runuser -u postgres -- "$@"; else "$@"; fi
}

up_native() {
    local pgbin
    pgbin="$(find_pgbin)" || {
        echo "FATAL: --native needs Postgres binaries (initdb/pg_ctl) on PATH or /usr/lib/postgresql/*/bin" >&2
        exit 1
    }
    echo "== infra up (native Postgres · ${pgbin}) =="
    mkdir -p "${RUN_DIR}"
    [ "$(id -u)" = "0" ] && chown -R postgres "${RUN_DIR}"
    if [ ! -s "${PGDATA}/PG_VERSION" ]; then
        pg_run "${pgbin}/initdb" -D "${PGDATA}" -U "${PG_USER}" --auth=trust -E UTF8 >"${RUN_DIR}/initdb.log" 2>&1
    fi
    if ! pg_run "${pgbin}/pg_ctl" -D "${PGDATA}" status >/dev/null 2>&1; then
        pg_run "${pgbin}/pg_ctl" -D "${PGDATA}" -l "${RUN_DIR}/server.log" \
            -o "-p ${PG_PORT} -c listen_addresses=localhost" -w start
    fi
    pg_run "${pgbin}/createdb" -h localhost -p "${PG_PORT}" -U "${PG_USER}" "${PG_DB}" 2>/dev/null || true
    summary "native · ${PGDATA}" " --native"
}

down_native() {
    local pgbin; pgbin="$(find_pgbin)" || return 0
    pg_run "${pgbin}/pg_ctl" -D "${PGDATA}" -w stop >/dev/null 2>&1 || true
    echo "native infra stopped (data kept; 'destroy --native' wipes it)"
}

case "${SUBCMD}" in
    up)      if [ "${BACKEND}" = native ]; then up_native; else up_docker; fi ;;
    down)    if [ "${BACKEND}" = native ]; then down_native; else docker_compose down; fi ;;
    destroy) if [ "${BACKEND}" = native ]; then down_native; rm -rf "${RUN_DIR}"; else docker_compose down -v; fi ;;
    status)  if [ "${BACKEND}" = native ]; then
                 pgbin="$(find_pgbin)" && pg_run "${pgbin}/pg_ctl" -D "${PGDATA}" status 2>/dev/null || echo "native infra not running"
             else docker_compose ps; fi ;;
    dsn)     dsn ;;
esac
