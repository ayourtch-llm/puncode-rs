#!/usr/bin/env bash
#
# Everything that has to hold before a commit, in one command that fails.
#
#   ./scripts/verify.sh && git commit ...
#
# This exists because it did not. A commit was once pushed reporting a clean
# workspace while two tests were failing: the shell line ran `cargo test` and
# then `git commit` regardless, because `&&` had been left out of a long chain.
# The failure was invisible in the output and the report said green.
#
# So "verified" is one script with one exit code, rather than whatever sequence
# was typed that time.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

failed=0
note() { printf '  %-10s %s\n' "$1" "$2"; }

# Formatting first: it rewrites files, and a scripted edit written against
# unformatted code silently misses after it runs.
if cargo fmt --check >/dev/null 2>&1; then
    note "fmt" "clean"
else
    note "fmt" "NOT FORMATTED — run cargo fmt"
    failed=1
fi

clippy_output=$(cargo clippy --all-targets 2>&1)
clippy_problems=$(printf '%s\n' "$clippy_output" | grep -cE '^(error|warning)' || true)
if [[ "$clippy_problems" -eq 0 ]]; then
    note "clippy" "0"
else
    note "clippy" "$clippy_problems problem(s)"
    printf '%s\n' "$clippy_output" | grep -E '^(error|warning)' -A4 | head -30
    failed=1
fi

test_output=$(cargo test --workspace 2>&1)
test_code=$?
passed=$(printf '%s\n' "$test_output" | awk '/test result: ok/ {sum+=$4} END {print sum+0}')
if [[ "$test_code" -eq 0 ]]; then
    note "tests" "$passed passing"
else
    note "tests" "FAILED"
    # The names, not the whole log: a wall of output is how a failure gets
    # scrolled past.
    printf '%s\n' "$test_output" | grep -E '^---- .* stdout' | sed 's/^/    /'
    failed=1
fi

if [[ -n "$(git status --porcelain)" ]]; then
    note "tree" "$(git status --porcelain | wc -l | tr -d ' ') uncommitted change(s)"
else
    note "tree" "clean"
fi

if [[ "$failed" -ne 0 ]]; then
    echo
    echo "NOT VERIFIED — do not commit."
    exit 1
fi

echo
echo "verified"
