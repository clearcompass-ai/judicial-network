# Judicial Network — make targets
#
# Versioning:
#   judicial-network v0.0.1
#     requires attesta v1.5.2 (Go module — bumped from v0.1.0 over
#                              PRs #24-#27: AdmissionEnforced (v1.5.0),
#                              VerifyComplete Stage 6 (v1.4.0), RFC 6979
#                              SignEntry (v1.5.2))
#     requires ledger   main  (HTTP, run via deployment/local/; the
#                              ledger self-gates Stage 6 admission via
#                              admission.LedgerPolicyResolver, default ON)
#
# All targets use POSIX sh and are intended to run in CI without
# relying on developer tooling.

GO          ?= go
SDK_MODULE  := github.com/clearcompass-ai/attesta
JN_VERSION  := 0.0.1

# Where compiled binaries land. Override on the make line if you
# want to install to ~/.local/bin or similar.
BIN_DIR     ?= ./bin

WALK_COMPOSE := docker compose -f deployment/local/docker-compose.walkthrough.yml

.PHONY: help build test test-short test-race vet tidy clean version \
        audit-sdk lint judicial-cli network-api court-tools provider-tools \
        aggregator install-bins \
        walkthrough-up walkthrough-down walkthrough-logs walkthrough-status \
        smoke

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

version: ## Print judicial-network version + dep pins
	@echo "judicial-network    $(JN_VERSION)"
	@echo "attesta (Go module) $$($(GO) list -m -f '{{.Version}}' $(SDK_MODULE))"
	@echo "ledger (HTTP)       main    (run via 'make walkthrough-up')"

# ────────────────────────────────────────────────────────────────────
# Build
# ────────────────────────────────────────────────────────────────────

build: ## Compile every package (sanity, no binaries written)
	$(GO) build ./...

LDFLAGS := -X main.Version=$(JN_VERSION)

judicial-cli: ## Build cmd/judicial-cli into ./bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/judicial-cli ./cmd/judicial-cli

network-api: ## Build cmd/network-api into ./bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/network-api ./cmd/network-api

court-tools: ## Build tools/court-tools into ./bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/court-tools ./tools/court-tools/cmd/court-tools

provider-tools: ## Build tools/provider-tools into ./bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/provider-tools ./tools/provider-tools/cmd/provider-tools

aggregator: ## Build tools/aggregator into ./bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/aggregator ./tools/aggregator/cmd/aggregator

# The standalone witness daemon lives in its own repo
# (github.com/clearcompass-ai/standalone-witness — extracted from
# clearcompass-ai/ledger at v1.2.0). judicial-network does NOT
# ship a witness binary; deployments consume the standalone-witness
# module directly:
#     go install github.com/clearcompass-ai/standalone-witness@<ver>
# JN's previous tools/witness/cmd/witness/ daemon (923 LOC) duplicated
# that module's source and was removed at the v1.2.0 alignment.

install-bins: judicial-cli network-api court-tools provider-tools aggregator ## Build all 5 binaries into ./bin/
	@echo ""
	@echo "binaries in $(BIN_DIR)/:"
	@ls -la $(BIN_DIR)/

# ────────────────────────────────────────────────────────────────────
# Quickstart — VC / evaluator path
# ────────────────────────────────────────────────────────────────────
#
# `make quickstart` mints the walkthrough's actor cast (5 did:key +
# 4 did:pkh across 4 EVM chains) and writes a sourced env file with
# every variable the walkthrough scripts use.
#
# It does NOT boot the ledger. The ledger runs in its own repo via
# `make integration-up` (offline, fake-gcs-server, no GCP) — see
# QUICKSTART.md.
#
# Prerequisites enforced via quickstart-preflight:
#   - LEDGER_URL_DAVIDSON (the trial-court ledger URL, e.g.
#     http://localhost:8080)
#   - LEDGER_URL_COA      (the appellate ledger URL, e.g.
#     http://localhost:8081)
#   - LEDGER_LOG_DID_DAVIDSON, LEDGER_LOG_DID_COA — the LogDID env
#     vars baked into the ledger's compose. With the offline
#     integration topology these are:
#         did:web:node-a.example   (Davidson role)
#         did:web:node-b.example   (COA role)
#
# Idempotent: re-running keeps existing keys; pass FORCE_RESET=1 to
# discard and re-mint.

KEYS_DIR ?= ./bin/keys
ENV_FILE ?= ./bin/walkthrough.env

.PHONY: quickstart quickstart-preflight quickstart-keys quickstart-env quickstart-clean

quickstart-preflight: ## Validate quickstart prerequisites (ledger URLs + LogDIDs)
	@for v in LEDGER_URL_DAVIDSON LEDGER_URL_COA LEDGER_LOG_DID_DAVIDSON LEDGER_LOG_DID_COA; do \
	  eval "val=\$$$$v"; \
	  if [ -z "$$val" ]; then \
	    echo "FAIL: $$v is unset"; \
	    echo ""; \
	    echo "judicial-network does NOT boot the ledger; it expects the"; \
	    echo "ledger to be running already. The default offline topology"; \
	    echo "is in the LEDGER repo:"; \
	    echo ""; \
	    echo "  cd ../ledger && make integration-up"; \
	    echo ""; \
	    echo "Then export back here:"; \
	    echo "  export LEDGER_URL_DAVIDSON=http://localhost:8080"; \
	    echo "  export LEDGER_URL_COA=http://localhost:8081"; \
	    echo "  export LEDGER_LOG_DID_DAVIDSON=did:web:node-a.example"; \
	    echo "  export LEDGER_LOG_DID_COA=did:web:node-b.example"; \
	    echo ""; \
	    echo "See QUICKSTART.md for the full sequence."; \
	    exit 1; \
	  fi; \
	done
	@echo "preflight ok: 4 ledger env vars set"
	@curl -fsS "$$LEDGER_URL_DAVIDSON/healthz" >/dev/null 2>&1 || { \
	  echo "FAIL: $$LEDGER_URL_DAVIDSON not reachable; is the ledger running?"; \
	  echo "      tip: cd ../ledger && make integration-up"; \
	  exit 1; \
	}
	@curl -fsS "$$LEDGER_URL_COA/healthz" >/dev/null 2>&1 || { \
	  echo "FAIL: $$LEDGER_URL_COA not reachable; is the second node up?"; \
	  exit 1; \
	}
	@echo "ledgers reachable: $$LEDGER_URL_DAVIDSON + $$LEDGER_URL_COA"

quickstart-keys: judicial-cli ## Mint walkthrough actor cast (5 did:key + 4 did:pkh)
	@mkdir -p $(KEYS_DIR)
	@if [ "$$FORCE_RESET" = "1" ]; then \
	  rm -f $(KEYS_DIR)/*.key.json; \
	  echo "FORCE_RESET=1 — keys directory cleared"; \
	fi
	@# 5 T1 / T2 court personnel (did:key)
	@for actor in clerk-brown cooper davis judge-adams justice-edwards judge-lewis magistrate-owens atty-murphy; do \
	  f="$(KEYS_DIR)/$$actor.key.json"; \
	  if [ -f "$$f" ]; then \
	    echo "skip  $$actor (already minted; FORCE_RESET=1 to re-mint)"; \
	  else \
	    $(BIN_DIR)/judicial-cli keygen --out "$$f" >/dev/null; \
	    echo "mint  $$actor → did:key"; \
	  fi; \
	done
	@# 4 T3 party principals on 4 different EVM chains (did:pkh)
	@$(MAKE) --no-print-directory _mint_pkh ACTOR=acme-ceo        CHAIN=1
	@$(MAKE) --no-print-directory _mint_pkh ACTOR=beta-cfo        CHAIN=137
	@$(MAKE) --no-print-directory _mint_pkh ACTOR=anderson-mother CHAIN=8453
	@$(MAKE) --no-print-directory _mint_pkh ACTOR=anderson-father CHAIN=10
	@echo ""
	@echo "actor cast in $(KEYS_DIR)/:"
	@ls $(KEYS_DIR)/*.key.json | xargs -I{} basename {} | sort

# Internal helper, not exposed via help.
_mint_pkh:
	@f="$(KEYS_DIR)/$(ACTOR).key.json"; \
	if [ -f "$$f" ]; then \
	  echo "skip  $(ACTOR) (already minted)"; \
	else \
	  $(BIN_DIR)/judicial-cli keygen --out "$$f" \
	    --method pkh-eip155 --chain-id $(CHAIN) >/dev/null; \
	  echo "mint  $(ACTOR) → did:pkh:eip155:$(CHAIN) (chain $(CHAIN))"; \
	fi

quickstart-env: quickstart-keys ## Write $(ENV_FILE) with every shell var the walkthrough uses
	@mkdir -p $(BIN_DIR)
	@{ \
	  echo "# walkthrough.env — auto-generated by 'make quickstart'."; \
	  echo "# Source from your shell:  source $(ENV_FILE)"; \
	  echo ""; \
	  echo "# ── Ledger endpoints + LogDIDs ────────────────────────"; \
	  echo "export DAVIDSON=\"$$LEDGER_URL_DAVIDSON\""; \
	  echo "export COA=\"$$LEDGER_URL_COA\""; \
	  echo "export DAVIDSON_LOG_DID=\"$$LEDGER_LOG_DID_DAVIDSON\""; \
	  echo "export COA_LOG_DID=\"$$LEDGER_LOG_DID_COA\""; \
	  echo ""; \
	  echo "# ── Actor DIDs (court personnel — did:key) ────────────"; \
	  for actor in clerk-brown cooper davis judge-adams justice-edwards judge-lewis magistrate-owens atty-murphy; do \
	    name=$$(echo $$actor | tr 'a-z-' 'A-Z_'); \
	    did=$$(jq -r '.did' "$(KEYS_DIR)/$$actor.key.json"); \
	    echo "export $$name=\"$$did\""; \
	  done; \
	  echo ""; \
	  echo "# ── Actor DIDs (party principals — did:pkh, 4 chains) ─"; \
	  for actor in acme-ceo beta-cfo anderson-mother anderson-father; do \
	    name=$$(echo $$actor | tr 'a-z-' 'A-Z_'); \
	    did=$$(jq -r '.did' "$(KEYS_DIR)/$$actor.key.json"); \
	    echo "export $$name=\"$$did\""; \
	  done; \
	  echo ""; \
	  echo "# ── Convenience aliases for the walkthrough narrative ─"; \
	  echo "export CLERK=\"\$$CLERK_BROWN\""; \
	  echo "export ADAMS=\"\$$JUDGE_ADAMS\""; \
	  echo "export EDWARDS=\"\$$JUSTICE_EDWARDS\""; \
	  echo "export LEWIS=\"\$$JUDGE_LEWIS\""; \
	  echo "export OWENS=\"\$$MAGISTRATE_OWENS\""; \
	  echo "export MURPHY=\"\$$ATTY_MURPHY\""; \
	  echo ""; \
	  echo "# ── Keys directory ───────────────────────────────────"; \
	  echo "export KEYS_DIR=\"$$(cd $(KEYS_DIR) && pwd)\""; \
	} > $(ENV_FILE)
	@echo ""
	@echo "wrote $(ENV_FILE)"
	@echo ""
	@echo "Next:"
	@echo "  source $(ENV_FILE)"
	@echo "  ./scripts/run-case-1-trial.sh"

quickstart: quickstart-preflight install-bins quickstart-env ## End-to-end: validate deps, build binaries, mint actor cast, write env file
	@echo ""
	@echo "quickstart complete. See QUICKSTART.md for next steps."

quickstart-clean: ## Remove minted keys + env file (does NOT touch the ledger)
	rm -rf $(KEYS_DIR) $(ENV_FILE)
	@echo "removed $(KEYS_DIR) and $(ENV_FILE)"

# ────────────────────────────────────────────────────────────────────
# Test
# ────────────────────────────────────────────────────────────────────

test: ## Full test suite (53 packages)
	$(GO) test -count=1 ./...

test-short: ## Short test suite (skip integration via -short)
	$(GO) test -count=1 -short ./...

test-race: ## Race detector across the touched-handler packages
	$(GO) test -count=1 -race -short \
	    ./api/... ./cases/... ./consortium/... ./monitoring/... \
	    ./onboarding/... ./topology/... ./verification/... ./tools/...

vet: ## go vet across all packages
	$(GO) vet ./...

tidy: ## go mod tidy + verify
	$(GO) mod tidy
	$(GO) mod verify

clean: ## Remove ./bin/ + test caches
	rm -rf $(BIN_DIR)
	$(GO) clean -testcache

# ────────────────────────────────────────────────────────────────────
# SDK mutation-gate audit
# ────────────────────────────────────────────────────────────────────

# audit-sdk ensures NO muEnable* gate has been flipped to false in
# the SDK that judicial-network depends on. Every muEnable constant
# is a load-bearing security gate; any value other than `true` in
# committed code is a regression.
audit-sdk: ## Fail if the pinned SDK ships any muEnable*=false
	@set -e; \
	SDK_PATH=$$($(GO) list -m -f '{{.Dir}}' $(SDK_MODULE)); \
	if [ -z "$$SDK_PATH" ] || [ ! -d "$$SDK_PATH" ]; then \
		echo "audit-sdk: cannot locate SDK source at $$SDK_PATH"; \
		exit 2; \
	fi; \
	echo "audit-sdk: scanning $$SDK_PATH"; \
	HITS=$$(grep -rn '^[[:space:]]*muEnable.*=[[:space:]]*false' \
	    --include='*.go' --exclude='*_test.go' "$$SDK_PATH" || true); \
	if [ -n "$$HITS" ]; then \
		echo "$$HITS"; \
		echo ""; \
		echo "FAIL: SDK ships disabled mutation gates (above)."; \
		echo "Every muEnable* constant must be true in committed code."; \
		exit 1; \
	fi; \
	echo "audit-sdk: PASS — no disabled mutation gates"

lint: vet audit-sdk ## All static checks (vet + audit-sdk)

# ────────────────────────────────────────────────────────────────────
# Walkthrough topology (JN-side tools layered atop the ledger compose)
# ────────────────────────────────────────────────────────────────────
#
# The walkthrough at docs/walkthrough/ is the canonical end-to-end
# integration story. It runs:
#   - 2 ledgers (Davidson :8080, COA :8081), via the LEDGER repo's
#     deployment/local/docker-compose.dev.yml (`make dev-up` there).
#   - JN-side tools (court-tools :8090, provider-tools :8091),
#     via THIS repo's deployment/local/docker-compose.walkthrough.yml.
#   - The judicial-cli (built into ./bin/) drives both layers.
#
# `make walkthrough-up` boots ONLY the JN-side tools layer. Boot
# the ledger layer first via `make -C ../ledger dev-up`.

walkthrough-up: install-bins ## Boot the JN-side tools layer (court-tools + provider-tools)
	$(WALK_COMPOSE) up -d --build
	@echo ""
	@echo "Running. Endpoints:"
	@echo "  court-tools     :8090"
	@echo "  provider-tools  :8091"
	@echo "  judicial-cli    $(BIN_DIR)/judicial-cli"
	@echo ""
	@echo "Continue with: docs/walkthrough/03-tools.md"

walkthrough-down: ## Tear down the JN-side tools layer
	$(WALK_COMPOSE) down -v

walkthrough-logs: ## Tail logs from court-tools + provider-tools
	$(WALK_COMPOSE) logs -f

walkthrough-status: ## Show service status
	$(WALK_COMPOSE) ps

# ────────────────────────────────────────────────────────────────────
# Smoke test — proves the walkthrough's CLI flow is actionable
# ────────────────────────────────────────────────────────────────────
#
# Builds the binaries, exercises the CLI's offline subcommands
# (keygen, version, help) without requiring a running ledger. The
# full HTTP-flow walkthrough is gated by ledger availability and
# documented under docs/walkthrough/.

smoke: install-bins ## Walkthrough-CLI smoke test (offline; no ledger required)
	@set -e; \
	TMPDIR=$$(mktemp -d -t jn-smoke-XXXXXX); \
	trap "rm -rf $$TMPDIR" EXIT; \
	echo "=== judicial-cli version ==="; \
	$(BIN_DIR)/judicial-cli version; \
	echo ""; \
	echo "=== judicial-cli keygen --method key (did:key path) ==="; \
	$(BIN_DIR)/judicial-cli keygen --method key --out $$TMPDIR/k1; \
	test -f $$TMPDIR/k1; \
	echo ""; \
	echo "=== judicial-cli keygen --method pkh-eip155 (did:pkh path) ==="; \
	$(BIN_DIR)/judicial-cli keygen --method pkh-eip155 --out $$TMPDIR/k2; \
	test -f $$TMPDIR/k2; \
	echo ""; \
	echo "=== judicial-cli help (commands surfaced) ==="; \
	$(BIN_DIR)/judicial-cli 2>&1 | head -20; \
	echo ""; \
	echo "smoke: PASS"
