# Judicial Network — make targets
#
# Versioning:
#   judicial-network v0.0.1
#     requires attesta v0.1.0 (Go module)
#     requires ledger   v0.1.0 (HTTP, run via deployment/local/)
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
        aggregator witness install-bins \
        walkthrough-up walkthrough-down walkthrough-logs walkthrough-status \
        smoke

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

version: ## Print judicial-network version + dep pins
	@echo "judicial-network    $(JN_VERSION)"
	@echo "attesta (Go module) $$($(GO) list -m -f '{{.Version}}' $(SDK_MODULE))"
	@echo "ledger (HTTP)       v0.1.0  (run via 'make walkthrough-up')"

# ─────────────────────────────────────────────────────────────────────
# Build
# ─────────────────────────────────────────────────────────────────────

build: ## Compile every package (sanity, no binaries written)
	$(GO) build ./...

LDFLAGS := -X main.Version=$(JN_VERSION)

judicial-cli: ## Build cmd/judicial-cli into ./bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/judicial-cli ./cmd/judicial-cli

network-api: ## Build cmd/network-api into ./bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/network-api ./cmd/network-api

court-tools: ## Build tools/cmd/court-tools into ./bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/court-tools ./tools/cmd/court-tools

provider-tools: ## Build tools/cmd/provider-tools into ./bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/provider-tools ./tools/cmd/provider-tools

aggregator: ## Build tools/cmd/aggregator into ./bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/aggregator ./tools/cmd/aggregator

witness: ## Build tools/cmd/witness into ./bin/
	@mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/witness ./tools/cmd/witness

install-bins: judicial-cli network-api court-tools provider-tools aggregator witness ## Build all 6 binaries into ./bin/
	@echo ""
	@echo "binaries in $(BIN_DIR)/:"
	@ls -la $(BIN_DIR)/

# ─────────────────────────────────────────────────────────────────────
# Test
# ─────────────────────────────────────────────────────────────────────

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

# ─────────────────────────────────────────────────────────────────────
# SDK mutation-gate audit
# ─────────────────────────────────────────────────────────────────────

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

# ─────────────────────────────────────────────────────────────────────
# Walkthrough topology (JN-side tools layered atop the ledger compose)
# ─────────────────────────────────────────────────────────────────────
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

# ─────────────────────────────────────────────────────────────────────
# Smoke test — proves the walkthrough's CLI flow is actionable
# ─────────────────────────────────────────────────────────────────────
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
