#!/usr/bin/env bash
# Compare the hermetic Criterion benches on the working tree against a released
# tag, both built and run on this machine. Published numbers from an older run
# on other hardware are not a regression signal.
#
# Usage:
#   scripts/bench-baseline.sh            # working tree vs the latest tag
#   scripts/bench-baseline.sh v0.21.0    # ... vs another ref
#
# Runs one bench process at a time. The two trees build into separate target
# dirs, since sharing one makes Cargo reuse a build-script output across
# checkouts whose build.rs differ. They share only CRITERION_HOME, which is
# what carries the baseline. Nothing else should be benchmarking meanwhile.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE_REF="${1:-$(git -C "$ROOT" describe --tags --abbrev=0)}"
BASE_NAME="${BASE_REF//\//-}"
# recursive_compare is excluded: it needs a live resolver and a live Unbound.
BENCHES=(hot_path throughput dnssec)

WORK="$(mktemp -d "${TMPDIR:-/tmp}/numa-bench-baseline.XXXXXX")"
export CRITERION_HOME="$ROOT/target/criterion-baseline"
BASE_TARGET="$ROOT/target/baseline-$BASE_NAME"
RESULT="$ROOT/target/baseline-vs-$BASE_NAME.log"
BASE_TREE="$WORK/base"

cleanup() {
  git -C "$ROOT" worktree remove --force "$BASE_TREE" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

git -C "$ROOT" rev-parse --verify "$BASE_REF^{commit}" >/dev/null

echo "==> baseline $BASE_REF vs working tree ($(git -C "$ROOT" rev-parse --short HEAD))"
echo "==> criterion data: $CRITERION_HOME"

echo "==> checking out $BASE_REF"
git -C "$ROOT" worktree add --detach "$BASE_TREE" "$BASE_REF" >/dev/null

BENCH_ARGS=("${BENCHES[@]/#/--bench=}")

echo "==> recording $BASE_REF"
(cd "$BASE_TREE" && CARGO_TARGET_DIR="$BASE_TARGET" \
  cargo bench "${BENCH_ARGS[@]}" -- --save-baseline "$BASE_NAME") 2>&1 | tail -3

# Lenient because benches added since the base ref have no baseline to compare
# against, and strict mode panics on the first one.
echo "==> comparing working tree"
(cd "$ROOT" && cargo bench "${BENCH_ARGS[@]}" -- --baseline-lenient "$BASE_NAME") 2>&1 | tee "$RESULT"

echo
echo "==> regressions vs $BASE_REF"
# -B6 rather than -B4: a throughput group puts five lines between the bench
# name and its verdict.
grep -B6 "Performance has regressed" "$RESULT" | grep -vE "^Benchmarking|^--$|^$" || echo "    none"
echo
echo "==> full output: $RESULT"
