#!/usr/bin/env bash
#
# Runs puncode-security against the bundled fixtures and reports what it found.
#
# Each fixture has known planted flaws, documented in docs/fixtures.md — kept
# out of the fixture directories so a scan cannot simply read the answers. The
# counts below say what a healthy scan should report.
#
#   ./scripts/scan-fixtures.sh                     # hosted Codex credentials
#   ./scripts/scan-fixtures.sh --local http://host:8080/v1 --model my-model
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Outside the repository on purpose: a fixture lives inside this checkout, so
# the checkout is the protected scan root and results may not be written into it.
OUT="${OUT_DIR:-${TMPDIR:-/tmp}/puncode-fixture-scans}"
BIN="${PUNCODE_BIN:-$ROOT/target/debug/puncode-security}"
BASE_URL="" MODEL="" EXTRA=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            sed -n '3,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        --local)  BASE_URL="$2"; shift 2 ;;
        --model)  MODEL="$2"; shift 2 ;;
        --)       shift; EXTRA+=("$@"); break ;;
        *)        EXTRA+=("$1"); shift ;;
    esac
done

if [[ ! -x "$BIN" ]]; then
    echo "no binary at $BIN — run: cargo build -p puncode-security-cli" >&2
    exit 2
fi

# Fixture name and the number of flaws planted in it, per docs/fixtures.md.
FIXTURES=("flask-injection:2" "c-memory:3")

mkdir -p "$OUT"
failures=0

for entry in "${FIXTURES[@]}"; do
    name="${entry%%:*}"
    expected="${entry##*:}"
    dir="$OUT/$name"
    rm -rf "$dir"

    args=(scan "$ROOT/fixtures/$name" --output-dir "$dir" --json)
    if [[ -n "$BASE_URL" ]]; then
        # A local endpoint needs the request reshaped for templates that accept
        # only one system message, and some key must be present even if unused.
        args+=(--base-url "$BASE_URL" --endpoint-compat merge-system)
        : "${OPENAI_API_KEY:=local-endpoint}"
        export OPENAI_API_KEY
    fi
    [[ -n "$MODEL" ]] && args+=(--model "$MODEL")
    args+=("${EXTRA[@]}")

    printf '=== %s (expecting %s findings) ===\n' "$name" "$expected"
    set +e
    "$BIN" "${args[@]}" > "$OUT/$name.log" 2>&1
    code=$?
    set -e

    found=$(python3 - "$dir" <<'PY'
import json, sys, pathlib
path = pathlib.Path(sys.argv[1]) / "findings.json"
try:
    data = json.loads(path.read_text())
    items = data.get("findings", data if isinstance(data, list) else [])
    print(len(items))
except Exception:
    print(-1)
PY
)
    if [[ "$found" -lt 0 ]]; then
        echo "  no findings.json — see $OUT/$name.log"
        failures=$((failures + 1))
    else
        printf '  found %s of %s expected (exit %s)\n' "$found" "$expected" "$code"
        [[ "$found" -lt "$expected" ]] && failures=$((failures + 1))
    fi
    printf '  results: %s\n\n' "$dir"
done

if [[ "$failures" -gt 0 ]]; then
    echo "$failures fixture(s) came up short — the scan missed known flaws."
    exit 1
fi
echo "every fixture reported at least its planted findings."
