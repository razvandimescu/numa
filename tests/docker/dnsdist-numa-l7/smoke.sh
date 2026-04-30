#!/usr/bin/env bash
# Smoke test for dnsdist L7 → numa over plain TCP with PROXY v2.
# Client sends UDP to dnsdist; dnsdist transmuxes to TCP and prepends a
# PROXY v2 header at connection open.
#
# Asserts:
#   1. dig +udp through dnsdist returns a real answer.
#   2. numa's transport.tcp counter increments (proves dnsdist→numa hop
#      is TCP, not UDP — i.e. tcpOnly=true is in effect).
#   3. numa's proxy_protocol.accepted increments (proves the PROXY header
#      was parsed and the real client IP propagated).
#   4. No rejections or timeouts on numa's pp2 layer.
#
# Requirements: docker (with compose v2), dig, curl, jq.

set -euo pipefail

cd "$(dirname "$0")"

GREEN="\033[32m"; RED="\033[31m"; DIM="\033[90m"; RESET="\033[0m"
pass() { printf "  ${GREEN}✓${RESET} %s\n" "$1"; }
fail() { printf "  ${RED}✗${RESET} %s\n" "$1"; exit 1; }

for tool in docker dig curl jq; do
  command -v "$tool" >/dev/null || fail "missing tool: $tool"
done

cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    printf "${DIM}KEEP=1 — leaving stack running. tear down with: docker compose -f %s down -v${RESET}\n" "$PWD/docker-compose.yml"
    return
  fi
  docker compose down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "── dnsdist L7 → numa PROXY v2 smoke test ──"

echo "  building & starting stack..."
docker compose up -d --build >/dev/null

echo -n "  waiting for numa /health "
ready=0
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:15381/health >/dev/null 2>&1; then
    echo " ok"; ready=1; break
  fi
  echo -n "."
  sleep 1
done
[ "$ready" = "1" ] || fail "numa /health never came up"

echo -n "  waiting for dnsdist UDP listener "
ready=0
for _ in $(seq 1 30); do
  if dig +short +time=1 +tries=1 @127.0.0.1 -p 15454 example.com >/dev/null 2>&1; then
    echo " ok"; ready=1; break
  fi
  echo -n "."
  sleep 1
done
[ "$ready" = "1" ] || fail "dnsdist not answering on 127.0.0.1:15454"

read -r baseline_pp baseline_tcp baseline_udp < <(curl -fsS http://127.0.0.1:15381/stats \
  | jq -r '[.proxy_protocol.accepted, .transport.tcp, .transport.udp] | @tsv')
pass "baseline: proxy_protocol.accepted=$baseline_pp transport.tcp=$baseline_tcp transport.udp=$baseline_udp"

echo "  dig +udp @127.0.0.1 -p 15454 example.com ..."
out=$(dig +short @127.0.0.1 -p 15454 example.com 2>/dev/null || true)
[ -n "$out" ] || fail "dig returned no answer (host→dnsdist→numa path broken)"
pass "answer: $(echo "$out" | tr '\n' ' ')"

# Issue a couple more so the counters move clearly above noise.
dig +short @127.0.0.1 -p 15454 cloudflare.com >/dev/null 2>&1 || true
dig +short @127.0.0.1 -p 15454 wikipedia.org  >/dev/null 2>&1 || true
sleep 1

read -r after_pp after_tcp after_udp rejected < <(curl -fsS http://127.0.0.1:15381/stats \
  | jq -r '[.proxy_protocol.accepted, .transport.tcp, .transport.udp, ([.proxy_protocol.rejected_untrusted, .proxy_protocol.rejected_signature, .proxy_protocol.timeout] | add)] | @tsv')

[ "$after_pp" -gt "$baseline_pp" ] || fail "proxy_protocol.accepted did not increment ($baseline_pp → $after_pp) — pp2 hook not firing"
pass "proxy_protocol.accepted incremented: $baseline_pp → $after_pp"

[ "$after_tcp" -gt "$baseline_tcp" ] || fail "transport.tcp did not increment ($baseline_tcp → $after_tcp) — dnsdist not transmuxing UDP→TCP, or tcpOnly=true not in effect"
pass "transport.tcp incremented (dnsdist transmuxed UDP→TCP): $baseline_tcp → $after_tcp"

[ "$rejected" = "0" ] || fail "rejected/timeout counters non-zero: $rejected"
pass "no pp2 rejections or timeouts"

# Sanity check: numa should not see UDP from the dnsdist→numa hop, since
# tcpOnly=true forces TCP. transport.udp can still increment from health
# probes / cache warming, so we only assert "didn't grow more than transport.tcp".
udp_growth=$((after_udp - baseline_udp))
tcp_growth=$((after_tcp - baseline_tcp))
[ "$tcp_growth" -ge "$udp_growth" ] || fail "transport.udp grew faster than transport.tcp ($udp_growth vs $tcp_growth) — tcpOnly=true may not be in effect"
pass "transport.tcp growth ($tcp_growth) ≥ transport.udp growth ($udp_growth) — UDP→TCP transmux confirmed"

echo
echo -e "${GREEN}all checks passed${RESET}"
