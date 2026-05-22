#!/usr/bin/env bash
# sod-guard.sh — Separation of Duties, enforced in CI.
#
# The judicial-network is the ENFORCER, not the custodian. It re-verifies
# evidence it pulls (zero-trust) and reacts (admission / halt), but it must
# host NO custodial gossip.Store and serve NO gossip feed — custody of fraud
# evidence belongs to the external auditor (attesta-tools services/auditor).
#
# attesta-tools enforces this structurally (the store impl is auditor-internal,
# un-importable). The JN can still REACH the SDK's store types, so this guard
# keeps the enforcer↔custodian split honest here: it fails if the JN ever
# constructs a gossip.Store or mounts the feed again.
#
# Run from the repo root. Exits non-zero on any violation.
set -euo pipefail

fail=0
viol() { printf '  ::error::%s\n' "$*"; fail=1; }

echo "== Separation of Duties: the enforcer hosts no custody =="

# (1) No gossip.Store implementation is constructed anywhere in the JN.
hits=$(grep -rnE '\b(NewInMemoryStore|NewPostgresStore)\b' --include='*.go' . 2>/dev/null | grep -v '_test\.go' || true)
if [ -n "$hits" ]; then
  viol "JN constructs a gossip.Store — custody belongs to the external auditor:"
  echo "$hits" | sed 's/^/    /'
else
  echo "  ok  no gossip.Store construction"
fi

# (2) No gossip feed is mounted/served by the JN.
hits=$(grep -rnE '\bNewFeedMount\b' --include='*.go' . 2>/dev/null | grep -v '_test\.go' || true)
if [ -n "$hits" ]; then
  viol "JN mounts a gossip feed — the /v1/gossip surface is the auditor's:"
  echo "$hits" | sed 's/^/    /'
else
  echo "  ok  no gossip feed mount"
fi

# (3) No re-introduced custody packages (the deleted gossipfeed/equivocation).
for dir in gossipfeed equivocation; do
  if [ -d "$dir" ]; then
    viol "$dir/ reintroduced — custody (store/feed) + detection are the auditor's"
  fi
done

echo
if [ "$fail" -eq 0 ]; then
  echo "SoD guard: PASS (enforcer hosts no custody)"
else
  echo "SoD guard: FAIL"
  exit 1
fi
