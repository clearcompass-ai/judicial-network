#!/usr/bin/env bash
#
# event-dictionary-check.sh — issue #67 Phase A drift gate.
#
# Diffs the canonical Event Dictionary (docs/event_dictionary_v1.8.md)
# against the JN's registered event identifiers and fails on drift.
#
# EXTRACTION (precise canonical sites only — no grep noise):
#
#   Dictionary: every leading "- **`event_name`**" bullet.
#
#   JN registrations: TWO canonical patterns:
#     1. `EventType: "event_name"` in cosignature_mix.go (the
#        admission-side policy registration site).
#     2. Map-key `"event_name":` in prerequisites.go (the
#        prerequisites-side declaration site).
#
#   Both patterns are deliberately narrow — random "string"
#   literals elsewhere in the codebase are not picked up.
#
# REPORTS:
#   - MISSING:  events the dictionary declares but JN has not
#               registered. Informational by default; --strict
#               makes them fatal (turn on once Phase C lands).
#   - EXTRA:    event-shaped identifiers in JN production code that
#               are NOT in the dictionary. Treated as FATAL —
#               every event MUST be in the canonical dictionary.
#   - NAMING:   the two verb-form violations (case_initiated,
#               "hearing") issue #67 Phase A renamed. Fatal — must
#               not regress.
#
# EXIT CODES:
#   0  — clean (no EXTRA, no NAMING drift).
#   1  — drift detected. CI rejects the PR.
#   2  — script error (missing dictionary, bad flag).
#
# USAGE:
#   ./scripts/event-dictionary-check.sh          # full report + gate
#   ./scripts/event-dictionary-check.sh --strict # MISSING also fatal
#
# CI: wired into .github/workflows/event-dictionary.yml.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DICT="$REPO_ROOT/docs/event_dictionary_v1.8.md"
STRICT=false
for arg in "$@"; do
    case "$arg" in
        --strict) STRICT=true ;;
        *) echo "Unknown flag: $arg" >&2; exit 2 ;;
    esac
done

if [[ ! -f "$DICT" ]]; then
    echo "FATAL: dictionary not found at $DICT" >&2
    exit 2
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# 1) Dictionary canonical events.
grep -oE '^- \*\*`[a-z][a-z0-9_]+`\*\*' "$DICT" \
    | sed 's/^- \*\*`//;s/`\*\*$//' \
    | sort -u > "$TMPDIR/dict.txt"

# 2) JN registrations — three canonical patterns across all
#    production deployment files (trial + sup_ct), excluding tests.
DEPLOY_GO_FILES=()
while IFS= read -r f; do DEPLOY_GO_FILES+=("$f"); done < <(
    find "$REPO_ROOT"/deployments/tn/trial \
         "$REPO_ROOT"/deployments/tn/sup_ct \
         -name '*.go' -not -name '*_test.go' 2>/dev/null
)
PREREQ_FILES=(
    "$REPO_ROOT"/deployments/tn/trial/prerequisites.go
    "$REPO_ROOT"/deployments/tn/sup_ct/prerequisites.go
)

# Pattern 1: EventType: "name" — anywhere in the production
# deployment tree (cosignature_mix.go AND motions_*.go AND any
# future per-section split).
{
    for f in "${DEPLOY_GO_FILES[@]}"; do
        grep -oE 'EventType:\s*"[a-z][a-z0-9_]+"' "$f" 2>/dev/null \
            | sed -E 's/.*"([a-z][a-z0-9_]+)".*/\1/' || true
    done
} > "$TMPDIR/jn_eventtype.txt"

# Pattern 2: map key "name": in a prerequisites declaration.
{
    for f in "${PREREQ_FILES[@]}"; do
        [[ -f "$f" ]] && grep -oE '^\s*"[a-z][a-z0-9_]+":' "$f" \
            | sed -E 's/^\s*"([a-z][a-z0-9_]+)":/\1/' || true
    done
} > "$TMPDIR/jn_prereq.txt"

# Pattern 3: RequiredAncestor: []string{"name"} — events
# referenced as prerequisites by other events MUST also exist as
# canonical event identifiers.
{
    for f in "${PREREQ_FILES[@]}"; do
        [[ -f "$f" ]] && grep -oE 'RequiredAncestor[^}]*"[a-z][a-z0-9_]+"' "$f" \
            | grep -oE '"[a-z][a-z0-9_]+"' \
            | tr -d '"' || true
    done
} > "$TMPDIR/jn_ancestor.txt"

cat "$TMPDIR/jn_eventtype.txt" "$TMPDIR/jn_prereq.txt" "$TMPDIR/jn_ancestor.txt" \
    | sort -u > "$TMPDIR/jn.txt"

comm -23 "$TMPDIR/dict.txt" "$TMPDIR/jn.txt" > "$TMPDIR/missing.txt"
comm -13 "$TMPDIR/dict.txt" "$TMPDIR/jn.txt" > "$TMPDIR/extra.txt"

DICT_COUNT=$(wc -l < "$TMPDIR/dict.txt")
JN_COUNT=$(wc -l < "$TMPDIR/jn.txt")
MISSING_COUNT=$(wc -l < "$TMPDIR/missing.txt")
EXTRA_COUNT=$(wc -l < "$TMPDIR/extra.txt")

echo "Event Dictionary v1.8 audit"
echo "==========================="
echo "Dictionary events           : $DICT_COUNT"
echo "JN-registered events (precise): $JN_COUNT"
echo "Missing from JN             : $MISSING_COUNT"
echo "Extra in JN                 : $EXTRA_COUNT"
echo

FATAL=false

# NAMING violations — always fatal.
NAMING_RE='^(case_initiated|hearing)$'
if grep -qE "$NAMING_RE" "$TMPDIR/jn.txt"; then
    echo "FATAL — naming-convention violations detected:" >&2
    grep -E "$NAMING_RE" "$TMPDIR/jn.txt" | sed 's/^/  - /' >&2
    echo "  (issue #67 Phase A renamed: case_initiated → case_initiation, hearing → hearing_convened_concluded)" >&2
    FATAL=true
fi

# EXTRA events — always fatal.
if [[ "$EXTRA_COUNT" -gt 0 ]]; then
    echo "FATAL — $EXTRA_COUNT event identifier(s) in JN production NOT in dictionary:" >&2
    sed 's/^/  + /' "$TMPDIR/extra.txt" >&2
    echo "  (add to docs/event_dictionary_v1.8.md OR move to a *_test.go file)" >&2
    FATAL=true
fi

# MISSING events — informational unless --strict.
if [[ "$MISSING_COUNT" -gt 0 ]]; then
    LABEL="INFO"
    [[ "$STRICT" == "true" ]] && LABEL="FATAL"
    echo "$LABEL — $MISSING_COUNT dictionary event(s) have no JN registration:" >&2
    sed 's/^/  - /' "$TMPDIR/missing.txt" >&2
    if [[ "$STRICT" == "true" ]]; then
        FATAL=true
    else
        echo "  (tracked under issue #67 Phase B/C; --strict gates on this)"
    fi
fi

if [[ "$FATAL" == "true" ]]; then
    exit 1
fi
echo "OK — no NAMING or EXTRA drift."
