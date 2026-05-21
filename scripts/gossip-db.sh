#!/usr/bin/env bash
# scripts/gossip-db.sh
#
# Local-dev launcher for the JN's durable gossip store — a Postgres
# instance in Docker, and NOTHING else (no Go build, no app). It mirrors
# the witness/ledger local-dev ergonomics (up / down / status), and takes
# every input from the environment with sane defaults.
#
# Outcome: stand up Postgres, then run network-api against it from env —
# the same config-from-env path the ledger uses:
#
#   ./scripts/gossip-db.sh up
#   export "$(./scripts/gossip-db.sh dsn)"      # API_GOSSIP_STORE_DSN=...
#   ./bin/network-api -config <config.json>     # durable gossip store live
#   ./scripts/gossip-db.sh down
#
# Env inputs (defaults shown) — the same vars the compose reads:
#   JN_GOSSIP_PG_USER  (attesta)
#   JN_GOSSIP_PG_PASS  (attestapassword)
#   JN_GOSSIP_PG_DB    (jn_gossip)
#   JN_GOSSIP_PG_PORT  (5433)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deployment/local/docker-compose.gossip-db.yml"
COMPOSE=(docker compose -f "${COMPOSE_FILE}")

PG_USER="${JN_GOSSIP_PG_USER:-attesta}"
PG_PASS="${JN_GOSSIP_PG_PASS:-attestapassword}"
PG_DB="${JN_GOSSIP_PG_DB:-jn_gossip}"
PG_PORT="${JN_GOSSIP_PG_PORT:-5433}"

dsn() {
    echo "API_GOSSIP_STORE_DSN=postgres://${PG_USER}:${PG_PASS}@localhost:${PG_PORT}/${PG_DB}?sslmode=disable"
}

cmd="${1:-up}"
case "${cmd}" in
    up)
        command -v docker >/dev/null 2>&1 || { echo "FATAL: docker not on PATH" >&2; exit 1; }
        echo "== starting JN gossip Postgres (docker only) =="
        "${COMPOSE[@]}" up -d
        echo "== waiting for Postgres to accept connections =="
        ready=0
        for i in $(seq 1 30); do
            if "${COMPOSE[@]}" exec -T gossip-db pg_isready -U "${PG_USER}" -d "${PG_DB}" >/dev/null 2>&1; then
                echo "  ready (attempt ${i})"
                ready=1
                break
            fi
            sleep 1
        done
        if [ "${ready}" -ne 1 ]; then
            echo "FATAL: Postgres did not become ready" >&2
            "${COMPOSE[@]}" logs --tail=20 gossip-db || true
            exit 1
        fi
        cat <<EOF

== JN gossip store Postgres UP ==
  container : jn-gossip-db (postgres:16-alpine)
  host port : ${PG_PORT}
  database  : ${PG_DB}

Run network-api against it (config-from-env, like the ledger):
  export "$(dsn)"
  ./bin/network-api -config <config.json>

The peer_gossip table is created automatically at boot
(PostgresStore.Migrate). Tear down with:
  ./scripts/gossip-db.sh down        # stop (keeps data volume)
  ./scripts/gossip-db.sh destroy     # stop + delete the data volume
EOF
        ;;
    down)
        "${COMPOSE[@]}" down
        ;;
    destroy)
        "${COMPOSE[@]}" down -v
        ;;
    status)
        "${COMPOSE[@]}" ps
        ;;
    dsn)
        dsn
        ;;
    -h|--help)
        sed -n '1,/^set -euo pipefail/p' "$0" | sed 's/^# \{0,1\}//'
        ;;
    *)
        echo "usage: $0 {up|down|destroy|status|dsn}" >&2
        exit 2
        ;;
esac
