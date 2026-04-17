#!/usr/bin/env bash
set -euo pipefail
cd ~/workspace/judicial-network

echo "=== Fix providers package declarations ==="
# The copy step flattened filenames — providers/ got courts package files.
for f in tools/providers/*.go; do
  sed -i '' 's/^package courts$/package providers/' "$f" 2>/dev/null || true
done

echo "=== Stage 2f: Delete business/ ==="
rm -rf business/

# Fix any remaining business/ imports.
echo "→ Checking for stale business/ imports..."
STALE=$(grep -rl '"github.com/clearcompass-ai/judicial-network/business' --include='*.go' . 2>/dev/null || true)
if [ -n "$STALE" ]; then
  echo "Found stale imports in:"
  echo "$STALE"
  # Remove business imports (they were absorbed into tools/courts/).
  for f in $STALE; do
    sed -i '' '/"github.com\/clearcompass-ai\/judicial-network\/business/d' "$f"
  done
  echo "→ Removed stale imports"
else
  echo "→ No stale imports found"
fi

echo ""
echo "=== Build check ==="
GOWORK=off go build ./... 2>&1
echo ""
echo "=== Test check ==="
GOWORK=off go test ./... 2>&1
