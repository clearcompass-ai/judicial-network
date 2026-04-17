#!/usr/bin/env bash
set -euo pipefail
cd ~/workspace/judicial-network

echo "=== Part II: Add tools/, absorb business/ ==="
echo ""
echo "Prerequisites: Part I completed (api/core/ and api/exchange/ exist)"
echo ""

# Verify Part I completed
if [ ! -f api/core/server.go ]; then
  echo "❌ api/core/server.go not found — run Part I first"
  exit 1
fi

# ─── Step 1: Create tools directory structure ────────────────────
echo "→ Creating tools/ structure..."
mkdir -p tools/cmd/court-tools
mkdir -p tools/cmd/provider-tools
mkdir -p tools/courts
mkdir -p tools/providers
mkdir -p tools/aggregator
mkdir -p tools/common

echo ""
echo "=== Structure created ==="
find tools -type d | sort
echo ""

# ─── Step 2: Absorb business/auth → tools/courts/auth.go ────────
echo "→ business/auth/ logic moves to tools/courts/auth.go"
echo "  business/handlers/ logic splits into tools/courts/{cases,orders,sealing}.go"
echo "  business/middleware/ moves to tools/courts/middleware.go"
echo ""

# ─── Step 3: Delete business/ ────────────────────────────────────
echo "→ Marking business/ for deletion after code generation"
echo ""

# ─── Step 4: Fix any remaining references to business/ ──────────
echo "→ Will fix imports in tests/ and deployments/ that reference business/"
echo ""

echo "=== Part II directory scaffold complete ==="
echo ""
echo "Next: generate code for each file in tools/"
echo ""
echo "  tools/common/config.go            — single config struct"
echo "  tools/common/exchange_client.go    — wraps exchange build-sign-submit"
echo "  tools/common/operator_client.go    — wraps operator scan/fetch"
echo "  tools/common/verify_client.go      — wraps verification API"
echo "  tools/common/db.go                 — Postgres connection"
echo "  tools/common/types.go              — shared request/response"
echo ""
echo "  tools/courts/server.go             — HTTP server + routes (:8090)"
echo "  tools/courts/auth.go               — SSO + mTLS (absorbs business/auth)"
echo "  tools/courts/middleware.go          — sealed filter (absorbs business/middleware)"
echo "  tools/courts/cases.go              — create, amend, transfer"
echo "  tools/courts/filings.go            — documents with artifacts"
echo "  tools/courts/orders.go             — judicial orders (Path B)"
echo "  tools/courts/sealing.go            — seal / unseal / expunge"
echo "  tools/courts/officers.go           — delegation management"
echo "  tools/courts/docket.go             — daily assignments"
echo ""
echo "  tools/providers/server.go          — HTTP server + routes (:8091)"
echo "  tools/providers/auth.go            — API key auth"
echo "  tools/providers/search.go          — public records search"
echo "  tools/providers/records.go         — case record retrieval"
echo "  tools/providers/documents.go       — public document access"
echo "  tools/providers/background.go      — cross-court background checks"
echo ""
echo "  tools/aggregator/scanner.go        — ScanFromPosition loop"
echo "  tools/aggregator/deserializer.go   — entry → domain fields"
echo "  tools/aggregator/indexer.go        — write to Postgres"
echo "  tools/aggregator/reconciler.go     — verify Postgres matches log"
echo "  tools/aggregator/schema.sql        — table definitions"
echo ""
echo "  tools/cmd/court-tools/main.go      — go run ./tools/cmd/court-tools"
echo "  tools/cmd/provider-tools/main.go   — go run ./tools/cmd/provider-tools"
echo ""
echo "After code generation:"
echo "  1. rm -rf business/"
echo "  2. Fix any remaining business/ imports"
echo "  3. GOWORK=off go build ./..."
echo "  4. GOWORK=off go test ./..."