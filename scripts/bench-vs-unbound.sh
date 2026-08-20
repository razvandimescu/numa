#!/usr/bin/env bash
# Spin up Numa-bench + Unbound, run the `recursive_compare --vs-unbound[-cold]`
# Criterion bench, tear down.
#
# Usage:
#   scripts/bench-vs-unbound.sh           # warm cache, forwarding mode
#   scripts/bench-vs-unbound.sh --cold    # unique subdomains, recursive mode
#
# One --cold run is not a result. The first of a session has been seen to read
# 2x slow on the Numa side alone, with Unbound in the same run unaffected, so a
# single run cannot separate a build from its turn in the order. Re-run any
# apparent regression, and compare only runs that repeat.
set -euo pipefail

NUMA_PORT="${NUMA_PORT:-5454}"
UNBOUND_PORT="${UNBOUND_PORT:-5456}"
UPSTREAM="${UPSTREAM:-9.9.9.9}"
UNBOUND_BIN="${UNBOUND_BIN:-/opt/homebrew/sbin/unbound}"
# Point NUMA_BIN at another build (see bench-baseline.sh's worktree) to bench a
# release against this tree's Unbound setup without rebuilding.
NUMA_BIN="${NUMA_BIN:-}"

if [[ "${1:-}" == "--cold" ]]; then
  MODE="cold"
  NUMA_TOML="benches/numa-bench-recursive.toml"
  BENCH_FLAG="--vs-unbound-cold"
else
  MODE="warm"
  NUMA_TOML="benches/numa-bench.toml"
  BENCH_FLAG="--vs-unbound"
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d -t numa-bench-vs-unbound.XXXXXX)"
NUMA_PID=""
UNBOUND_PID=""

cleanup() {
  [[ -n "$NUMA_PID" ]] && kill "$NUMA_PID" 2>/dev/null || true
  [[ -n "$UNBOUND_PID" ]] && kill "$UNBOUND_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

cat >"$WORK/unbound.conf" <<EOF
server:
    verbosity: 0
    interface: 127.0.0.1@$UNBOUND_PORT
    do-ip6: no
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    pidfile: "$WORK/unbound.pid"
    use-syslog: no
    logfile: "$WORK/unbound.log"
    cache-min-ttl: 60
    cache-max-ttl: 3600
    prefetch: yes
EOF

# Warm mode forwards to a public resolver (apples-to-apples with numa-bench
# which also forwards). Cold mode recurses from roots on both sides.
if [[ "$MODE" == "warm" ]]; then
  cat >>"$WORK/unbound.conf" <<EOF
forward-zone:
    name: "."
    forward-addr: $UPSTREAM
EOF
fi

echo "==> mode: $MODE (numa: $NUMA_TOML)"

if [[ -z "$NUMA_BIN" ]]; then
  echo "==> building numa (release)"
  cargo build --release --bin numa 2>&1 | tail -3
  NUMA_BIN="$ROOT/target/release/numa"
fi

echo "==> starting unbound on 127.0.0.1:$UNBOUND_PORT"
"$UNBOUND_BIN" -c "$WORK/unbound.conf" -d >"$WORK/unbound.stderr" 2>&1 &
UNBOUND_PID=$!

echo "==> starting numa-bench on 127.0.0.1:$NUMA_PORT ($("$NUMA_BIN" --version 2>&1 | head -1))"
"$NUMA_BIN" "$ROOT/$NUMA_TOML" >"$WORK/numa.log" 2>&1 &
NUMA_PID=$!

echo "==> waiting for both servers"
for i in $(seq 1 30); do
  ok_u=0; ok_n=0
  dig @127.0.0.1 -p "$UNBOUND_PORT" example.com +short +time=1 +tries=1 >/dev/null 2>&1 && ok_u=1
  dig @127.0.0.1 -p "$NUMA_PORT" example.com +short +time=1 +tries=1 >/dev/null 2>&1 && ok_n=1
  if [[ $ok_u -eq 1 && $ok_n -eq 1 ]]; then
    echo "    ready (after ${i}s)"
    break
  fi
  sleep 1
  if [[ $i -eq 30 ]]; then
    echo "ERROR: servers did not become ready"
    echo "--- unbound stderr ---"; tail -20 "$WORK/unbound.stderr" || true
    echo "--- numa log ---"; tail -20 "$WORK/numa.log" || true
    exit 1
  fi
done

echo "==> running cargo bench --bench recursive_compare -- $BENCH_FLAG"
cd "$ROOT"
cargo bench --bench recursive_compare -- "$BENCH_FLAG"
