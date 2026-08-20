#!/usr/bin/env bash
# What a cache entry costs a build, measured from its own /stats. Not a
# Criterion bench: the number only exists once a resolver has answered real
# queries.
#
# Cache entries are measured in two cohorts, signed and unsigned zones, because
# DO=1 upstream (#329) only inflates the answers that carry RRSIGs. Averaging
# the two hides the effect.
#
# Usage:
#   scripts/bench-footprint.sh            # working tree vs the latest tag
#   scripts/bench-footprint.sh --current  # working tree only
set -euo pipefail

DNS_PORT=5464
API_PORT=5391

SIGNED=(ietf.org isc.org iana.org ripe.net nlnetlabs.nl cloudflare.com
        quad9.net verisign.com internetsociety.org nic.cz fedoraproject.org
        debian.org icann.org arin.net nist.gov cira.ca paypal.com slack.com)
UNSIGNED=(kernel.org wikipedia.org facebook.com google.com amazon.com
          microsoft.com apple.com github.com reddit.com netflix.com youtube.com
          linkedin.com zoom.us dropbox.com spotify.com ebay.com
          stackoverflow.com nytimes.com rust-lang.org golang.org python.org
          nodejs.org)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/numa-footprint.XXXXXX")"
BASE_TREE="$WORK/base"
NUMA_PID=""

if [[ "${1:-}" == "--current" ]]; then
  BASE_REF=""
else
  BASE_REF="${1:-$(git -C "$ROOT" describe --tags --abbrev=0)}"
  BASE_TARGET="$ROOT/target/baseline-${BASE_REF//\//-}"
fi

cleanup() {
  [[ -n "$NUMA_PID" ]] && kill "$NUMA_PID" 2>/dev/null || true
  git -C "$ROOT" worktree remove --force "$BASE_TREE" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

CONFIG="$WORK/numa.toml"
cat >"$CONFIG" <<EOF
[server]
bind_addr = "127.0.0.1:$DNS_PORT"
api_port = $API_PORT
api_bind_addr = "127.0.0.1"
data_dir = "$WORK/data"

[upstream]
mode = "forward"
address = ["https://9.9.9.9/dns-query"]
timeout_ms = 10000

[blocking]
enabled = false

[proxy]
enabled = false

[dot]
enabled = false
EOF

start_numa() {
  "$1" "$CONFIG" >"$WORK/numa.log" 2>&1 &
  NUMA_PID=$!
}

stop_numa() {
  [[ -n "$NUMA_PID" ]] && kill "$NUMA_PID" 2>/dev/null || true
  wait "$NUMA_PID" 2>/dev/null || true
  NUMA_PID=""
}

# serve.rs binds the UDP listeners before it spawns the API, so a healthy API
# means the resolver is already answering.
wait_for_api() {
  for _ in $(seq 1 30); do
    curl -sf --max-time 1 "http://127.0.0.1:$API_PORT/health" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "ERROR: numa API never came up on $API_PORT"
  tail -20 "$WORK/numa.log"
  return 1
}

# entries and cache bytes after resolving one cohort, with the cache flushed
# first so the two cohorts never share a measurement.
cohort_bytes() {
  local label="$1"; shift
  curl -s --max-time 5 -X DELETE "http://127.0.0.1:$API_PORT/cache" >/dev/null
  # Serially: a parallel fan-out times some queries out under the 2s budget
  # and silently measures whichever subset survived.
  for d in "$@"; do
    dig @127.0.0.1 -p "$DNS_PORT" +noadflag +time=2 +tries=1 "$d" A >/dev/null 2>&1 || true
  done
  curl -s --max-time 5 "http://127.0.0.1:$API_PORT/stats" | python3 -c '
import json, sys
s = json.load(sys.stdin)
n = s["cache"]["entries"]
b = s["memory"]["cache_bytes"]
per = b / n if n else 0
print(f"    {sys.argv[1]:<10} entries={n:<4} cache_bytes={b:<8} per_entry={per:.0f}")
' "$label"
}

profile() {
  local bin="$1" label="$2"
  # numa prints its version on stderr
  echo "==> $label: $("$bin" --version 2>&1 | head -1)"

  start_numa "$bin"
  wait_for_api
  cohort_bytes unsigned "${UNSIGNED[@]}"
  cohort_bytes signed "${SIGNED[@]}"
  stop_numa
}

echo "==> building working tree"
(cd "$ROOT" && cargo build --release --bin numa) 2>&1 | tail -2
profile "$TARGET_DIR/release/numa" "working tree"

if [[ -n "$BASE_REF" ]]; then
  echo
  echo "==> building $BASE_REF"
  git -C "$ROOT" worktree add --detach "$BASE_TREE" "$BASE_REF" >/dev/null
  (cd "$BASE_TREE" && CARGO_TARGET_DIR="$BASE_TARGET" cargo build --release --bin numa) 2>&1 | tail -2
  profile "$BASE_TARGET/release/numa" "$BASE_REF"
fi
