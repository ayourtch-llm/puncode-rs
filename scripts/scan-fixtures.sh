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
#
# Stamped per run because the workbench registers a scan against its output
# directory and refuses to register a second one there. Reusing a path works
# exactly once and then fails on a UNIQUE constraint.
OUT="${OUT_DIR:-${TMPDIR:-/tmp}/puncode-fixture-scans/$(date +%Y%m%d-%H%M%S)}"
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

# Read from the corpus rather than repeated here: a second list drifts, and a
# stale expectation is a test that passes while measuring the wrong thing.
GROUND_TRUTH="${GROUND_TRUTH:-$ROOT/benchmark/ground-truth.json}"
mapfile -t FIXTURES < <(python3 -c "
import json, sys
corpus = json.load(open(sys.argv[1]))
for f in corpus['fixtures']:
    print(f\"{f['name']}:{len(f['flaws'])}\")
" "$GROUND_TRUTH")
if [[ ${#FIXTURES[@]} -eq 0 ]]; then
    echo "no fixtures in $GROUND_TRUTH" >&2
    exit 2
fi

mkdir -p "$OUT"
failures=0

for entry in "${FIXTURES[@]}"; do
    name="${entry%%:*}"
    expected="${entry##*:}"
    dir="$OUT/$name"
    rm -rf "$dir"

    # Scanned from a copy, not from the checkout. The fixtures live inside this
    # repository, so a commit during the run moves HEAD and the scan is refused
    # at the end with "Repository HEAD changed while the scan was running" —
    # after doing all the work. Losing an hour of scanning to an unrelated
    # commit is not a reasonable thing to ask of whoever runs this.
    snapshot="$OUT/$name.src"
    rm -rf "$snapshot"
    mkdir -p "$snapshot"
    cp -r "$ROOT/fixtures/$name/." "$snapshot/"
    ( cd "$snapshot" && git init -q && git add -A \
        && git -c user.email=fixtures@local -c user.name=fixtures commit -qm snapshot )

    args=(scan "$snapshot" --output-dir "$dir" --json)
    if [[ -n "$BASE_URL" ]]; then
        # A local endpoint needs the request reshaped for templates that accept
        # only one system message, and some key must be present even if unused.
        args+=(--base-url "$BASE_URL" --endpoint-compat merge-system)
        : "${OPENAI_API_KEY:=local-endpoint}"
        export OPENAI_API_KEY
    fi
    [[ -n "$MODEL" ]] && args+=(--model "$MODEL")
    args+=("${EXTRA[@]}")

    if [[ "$expected" -eq 0 ]]; then
        printf '=== %s (control - nothing planted) ===\n' "$name"
    else
        printf '=== %s (expecting %s findings) ===\n' "$name" "$expected"
    fi
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
        if [[ "$expected" -eq 0 ]]; then
            # On a control fixture anything reported is a false positive, which
            # decides trust more than recall does.
            printf '  %s false positive(s) (exit %s)\n' "$found" "$code"
            [[ "$found" -gt 0 ]] && failures=$((failures + 1))
        else
            printf '  found %s of %s expected (exit %s)\n' "$found" "$expected" "$code"
            [[ "$found" -lt "$expected" ]] && failures=$((failures + 1))
        fi
    fi
    printf '  results: %s\n\n' "$dir"
done

printf 'score this run:\n  puncode-security bench %s\n\n' "$OUT"

if [[ "$failures" -gt 0 ]]; then
    echo "$failures fixture(s) fell short - missed flaws, or noise on a control."
    exit 1
fi
echo "every fixture reported its planted findings, and the controls stayed quiet."
