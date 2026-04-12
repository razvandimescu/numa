#!/usr/bin/env bash
# Bench: Numa cold-cache recursive resolution vs dig (forwarded through system resolver)
#
# Measures cold-cache recursive resolution time for Numa.
# Flushes Numa's cache before each query to ensure cold-cache.
# Compares against dig querying a public recursive resolver (no cache advantage).
#
# Usage: ./scripts/bench-recursive.sh [numa_port]

set -euo pipefail

NUMA_ADDR="${NUMA_ADDR:-127.0.0.1}"
NUMA_PORT="${NUMA_PORT:-${1:-53}}"
API_PORT="${API_PORT:-5380}"
ROUNDS=3

DOMAINS=(
  "example.com"
  "rust-lang.org"
  "kernel.org"
  "signal.org"
  "archlinux.org"
  "openbsd.org"
  "git-scm.com"
  "sqlite.org"
  "wireguard.com"
  "mozilla.org"
)

GREEN='\033[0;32m'
AMBER='\033[0;33m'
CYAN='\033[0;36m'
DIM='\033[0;90m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${CYAN}${BOLD}Recursive DNS Resolution Benchmark${RESET}"
echo -e "${DIM}Numa (cold cache, recursive from root) vs dig @1.1.1.1 (public resolver)${RESET}"
echo -e "${DIM}Rounds per domain: ${ROUNDS}${RESET}"
echo ""

# Verify Numa is reachable
if ! dig @${NUMA_ADDR} -p ${NUMA_PORT} +short +time=3 +tries=1 example.com A &>/dev/null; then
  echo -e "${AMBER}Numa not responding on ${NUMA_ADDR}:${NUMA_PORT}${RESET}" >&2
  exit 1
fi

# Verify we can flush cache
if ! curl -s -X DELETE "http://${NUMA_ADDR}:${API_PORT}/cache" &>/dev/null; then
  echo -e "${AMBER}Cannot flush cache via API at ${NUMA_ADDR}:${API_PORT}${RESET}" >&2
  exit 1
fi

measure_ms() {
  local start end
  start=$(python3 -c 'import time; print(time.time())')
  eval "$1" &>/dev/null
  end=$(python3 -c 'import time; print(time.time())')
  python3 -c "print(round(($end - $start) * 1000, 1))"
}

printf "${BOLD}%-22s  %10s  %10s  %8s${RESET}\n" "Domain" "Numa (ms)" "1.1.1.1" "Delta"
printf "%-22s  %10s  %10s  %8s\n" "----------------------" "----------" "----------" "--------"

numa_total=0
dig_total=0
count=0

for domain in "${DOMAINS[@]}"; do
  numa_sum=0
  dig_sum=0

  for ((r=1; r<=ROUNDS; r++)); do
    # Flush Numa cache
    curl -s -X DELETE "http://${NUMA_ADDR}:${API_PORT}/cache" &>/dev/null
    sleep 0.05

    # Measure Numa (recursive from root, cold cache)
    ms=$(measure_ms "dig @${NUMA_ADDR} -p ${NUMA_PORT} +short +time=10 +tries=1 ${domain} A")
    numa_sum=$(python3 -c "print(round($numa_sum + $ms, 1))")

    # Measure dig against 1.1.1.1 (Cloudflare — warm cache, but shows baseline)
    ms=$(measure_ms "dig @1.1.1.1 +short +time=10 +tries=1 ${domain} A")
    dig_sum=$(python3 -c "print(round($dig_sum + $ms, 1))")
  done

  numa_avg=$(python3 -c "print(round($numa_sum / $ROUNDS, 1))")
  dig_avg=$(python3 -c "print(round($dig_sum / $ROUNDS, 1))")
  delta=$(python3 -c "d = round($numa_avg - $dig_avg, 1); print(f'+{d}' if d > 0 else str(d))")

  # Color the delta
  delta_color="$GREEN"
  if python3 -c "exit(0 if $numa_avg > $dig_avg * 1.5 else 1)" 2>/dev/null; then
    delta_color="$AMBER"
  fi

  printf "%-22s  %8s ms  %8s ms  ${delta_color}%6s ms${RESET}\n" "$domain" "$numa_avg" "$dig_avg" "$delta"

  numa_total=$(python3 -c "print(round($numa_total + $numa_avg, 1))")
  dig_total=$(python3 -c "print(round($dig_total + $dig_avg, 1))")
  count=$((count + 1))
done

echo ""
numa_mean=$(python3 -c "print(round($numa_total / $count, 1))")
dig_mean=$(python3 -c "print(round($dig_total / $count, 1))")
delta_mean=$(python3 -c "d = round($numa_mean - $dig_mean, 1); print(f'+{d}' if d > 0 else str(d))")

printf "${BOLD}%-22s  %8s ms  %8s ms  %6s ms${RESET}\n" "AVERAGE" "$numa_mean" "$dig_mean" "$delta_mean"

echo ""
echo -e "${DIM}Note: Numa resolves recursively from root hints (cold cache).${RESET}"
echo -e "${DIM}1.1.1.1 serves from Cloudflare's global cache (warm). The comparison${RESET}"
echo -e "${DIM}is intentionally unfair — it shows Numa's worst case vs the best case${RESET}"
echo -e "${DIM}of a global anycast resolver. Cached Numa queries resolve in <1ms.${RESET}"
