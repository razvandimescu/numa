#!/usr/bin/env bash
set -euo pipefail

API="${NUMA_API:-http://127.0.0.1:5380}"
DNS="${NUMA_DNS:-127.0.0.1}"
NUMA_BIN="${NUMA_BIN:-/usr/local/bin/numa}"
LAUNCHD_PLIST="/Library/LaunchDaemons/com.numa.dns.plist"

DOMAINS=(
  paypal.com ebay.com zoom.us slack.com discord.com
  microsoft.com apple.com meta.com oracle.com ibm.com
  docker.com kubernetes.io prometheus.io grafana.com terraform.io
  python.org nodejs.org golang.org wikipedia.org reddit.com
  stackoverflow.com stripe.com linear.app nytimes.com bbc.co.uk
  rust-lang.org fastly.com hetzner.com uber.com airbnb.com
  notion.so figma.com netflix.com spotify.com dropbox.com
  gitlab.com twitch.tv shopify.com vercel.app mozilla.org
)

stats() {
  curl -s "$API/query-log" | python3 -c "
import sys, json

data = json.load(sys.stdin)
rec = [q for q in data if q['path'] == 'RECURSIVE']
if not rec:
    print('No recursive queries in log.')
    sys.exit()

vals = sorted([q['latency_ms'] for q in rec])
n = len(vals)

print(f'Recursive queries: {n}')
print(f'  Avg:    {sum(vals)/n:.1f}ms')
print(f'  Median: {vals[n//2]:.1f}ms')
print(f'  P95:    {vals[int(n*0.95)]:.1f}ms')
print(f'  P99:    {vals[int(n*0.99)]:.1f}ms')
print(f'  Min:    {min(vals):.1f}ms')
print(f'  Max:    {max(vals):.1f}ms')
print(f'  <100ms: {sum(1 for v in vals if v < 100)}')
print(f'  <200ms: {sum(1 for v in vals if v < 200)}')
print(f'  <500ms: {sum(1 for v in vals if v < 500)}')
print(f'  >1s:    {sum(1 for v in vals if v >= 1000)}')
print()
print('Slowest 5:')
for q in sorted(rec, key=lambda q: q['latency_ms'], reverse=True)[:5]:
    print(f'  {q[\"latency_ms\"]:>8.1f}ms  {q[\"query_type\"]:5s}  {q[\"domain\"]:35s}  {q[\"rescode\"]}')
print()
print('Fastest 5:')
for q in sorted(rec, key=lambda q: q['latency_ms'])[:5]:
    print(f'  {q[\"latency_ms\"]:>8.1f}ms  {q[\"query_type\"]:5s}  {q[\"domain\"]:35s}  {q[\"rescode\"]}')
"
}

query_all() {
  local label="$1"
  echo "=== $label ==="
  for d in "${DOMAINS[@]}"; do
    printf "  %-25s " "$d"
    dig "@$DNS" "$d" A +noall +stats 2>/dev/null | grep "Query time"
  done
  echo
}

flush_cache() {
  curl -s -X DELETE "$API/cache" > /dev/null
  echo "Cache flushed ($(curl -s "$API/stats" | python3 -c "import sys,json; print(json.load(sys.stdin)['cache']['entries'])" 2>/dev/null || echo '?') entries)."
}

wait_for_api() {
  local attempts=0
  while ! curl -sf "$API/health" > /dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ $attempts -ge 20 ]; then
      echo "ERROR: API not reachable at $API after 10s" >&2
      exit 1
    fi
    sleep 0.5
  done
}

# restart_numa <config_toml_body>
# Writes config to a temp file, stops numa (launchd or manual), starts with that config.
restart_numa() {
  local config_body="$1"
  local tmpconf
  tmpconf=$(mktemp /tmp/numa-bench-XXXXXX)
  mv "$tmpconf" "${tmpconf}.toml"
  tmpconf="${tmpconf}.toml"
  echo "$config_body" > "$tmpconf"

  # Stop launchd-managed numa if active
  if sudo launchctl list com.numa.dns &>/dev/null; then
    sudo launchctl unload "$LAUNCHD_PLIST" 2>/dev/null || true
    sleep 1
  fi

  # Kill any remaining
  sudo killall numa 2>/dev/null || true
  sleep 2

  sudo "$NUMA_BIN" "$tmpconf" &
  wait_for_api
  sleep 4  # let TLD priming finish
  echo "numa ready (pid $(pgrep numa | head -1), config: $tmpconf)."
}

# Restore the launchd service
restore_launchd() {
  sudo killall numa 2>/dev/null || true
  sleep 1
  if [ -f "$LAUNCHD_PLIST" ]; then
    sudo launchctl load "$LAUNCHD_PLIST" 2>/dev/null || true
    echo "Restored launchd service."
  fi
}

run_pass() {
  local label="$1"
  flush_cache
  sleep 0.5
  query_all "$label"
  echo "=== $label — stats ==="
  stats
}

case "${1:-full}" in
  cold)
    echo "--- Cold cache benchmark ---"
    run_pass "Cold SRTT + Cold cache"
    ;;
  warm)
    echo "--- Warm SRTT benchmark ---"
    echo "Priming SRTT..."
    for d in "${DOMAINS[@]}"; do dig "@$DNS" "$d" A +short > /dev/null 2>&1; done
    run_pass "Warm SRTT + Cold cache"
    ;;
  stats)
    stats
    ;;
  compare-srtt)
    echo "============================================"
    echo "  A/B: SRTT OFF vs ON (dnssec off)"
    echo "============================================"
    echo

    restart_numa "$(cat <<'TOML'
[upstream]
mode = "recursive"
srtt = false
TOML
)"
    echo
    run_pass "SRTT OFF"

    echo
    echo "--------------------------------------------"
    echo

    restart_numa "$(cat <<'TOML'
[upstream]
mode = "recursive"
srtt = true
TOML
)"
    echo
    run_pass "SRTT ON"

    echo
    restore_launchd
    ;;
  compare-dnssec)
    echo "============================================"
    echo "  A/B: DNSSEC OFF vs ON (srtt on)"
    echo "============================================"
    echo

    restart_numa "$(cat <<'TOML'
[upstream]
mode = "recursive"
srtt = true

[dnssec]
enabled = false
TOML
)"
    echo
    run_pass "DNSSEC OFF"

    echo
    echo "--------------------------------------------"
    echo

    restart_numa "$(cat <<'TOML'
[upstream]
mode = "recursive"
srtt = true

[dnssec]
enabled = true
TOML
)"
    echo
    run_pass "DNSSEC ON"

    echo
    restore_launchd
    ;;
  compare-all)
    echo "============================================"
    echo "  Full A/B matrix"
    echo "  1. SRTT OFF + DNSSEC OFF (baseline)"
    echo "  2. SRTT ON  + DNSSEC OFF"
    echo "  3. SRTT ON  + DNSSEC ON"
    echo "============================================"
    echo

    # --- 1. Baseline ---
    restart_numa "$(cat <<'TOML'
[upstream]
mode = "recursive"
srtt = false

[dnssec]
enabled = false
TOML
)"
    echo
    run_pass "SRTT OFF + DNSSEC OFF"

    echo
    echo "--------------------------------------------"
    echo

    # --- 2. SRTT only ---
    restart_numa "$(cat <<'TOML'
[upstream]
mode = "recursive"
srtt = true

[dnssec]
enabled = false
TOML
)"
    echo
    run_pass "SRTT ON + DNSSEC OFF"

    echo
    echo "--------------------------------------------"
    echo

    # --- 3. Both ---
    restart_numa "$(cat <<'TOML'
[upstream]
mode = "recursive"
srtt = true

[dnssec]
enabled = true
TOML
)"
    echo
    run_pass "SRTT ON + DNSSEC ON"

    echo
    restore_launchd
    ;;
  full|*)
    echo "--- Full benchmark (cold → warm → SRTT-only) ---"
    echo

    flush_cache
    sleep 0.5
    query_all "Pass 1: Cold SRTT + Cold cache"

    flush_cache
    sleep 0.5
    query_all "Pass 2: Warm SRTT + Cold cache"

    echo "=== Pass 2 stats (SRTT-warm) ==="
    stats
    ;;
esac
