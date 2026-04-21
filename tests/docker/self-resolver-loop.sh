#!/usr/bin/env bash
#
# Reproducer for issue #122 — chicken-and-egg when numa is its own system
# resolver (HAOS add-on, Pi-hole-style container, laptop with
# resolv.conf → 127.0.0.1).
#
# Topology:
#   container /etc/resolv.conf  →  nameserver 127.0.0.1
#   numa bound on :53           →  upstream DoH by hostname (quad9)
#   numa boots → spawns blocklist download
#   reqwest::get → getaddrinfo("cdn.jsdelivr.net")
#     → loopback UDP :53 → numa → cache miss → DoH upstream
#     → getaddrinfo("dns.quad9.net") → same loop → glibc EAI_AGAIN
#
# Expected on master: both assertions FAIL (bug reproduced).
# Expected after bootstrap-IP fix: both assertions PASS.
#
# Requirements: docker (with internet access for external lists/DoH)
# Usage:        ./tests/docker/self-resolver-loop.sh

set -euo pipefail

cd "$(dirname "$0")/../.."

GREEN="\033[32m"; RED="\033[31m"; RESET="\033[0m"

pass() { printf "  ${GREEN}✓${RESET} %s\n" "$1"; }
fail() { printf "  ${RED}✗${RESET} %s\n" "$1"; printf "    %s\n" "$2"; FAILED=$((FAILED+1)); }
FAILED=0

OUT=/tmp/numa-self-resolver.out

echo "── self-resolver-loop: building + reproducing on debian:bookworm ──"
echo "  (first run is slow: image pull + cold cargo build, ~5-8 min)"
echo

docker run --rm \
    -v "$PWD:/src:ro" \
    -v numa-self-resolver-cargo:/root/.cargo \
    -v numa-self-resolver-target:/work/target \
    debian:bookworm bash -c '
set -e

# Phase 1: install deps + build with the container DNS as given by Docker
# (resolves deb.debian.org, static.rust-lang.org, crates.io).
apt-get update -qq && apt-get install -y -qq curl build-essential dnsutils 2>&1 | tail -3

if ! command -v cargo &>/dev/null; then
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --quiet
fi
. "$HOME/.cargo/env"

mkdir -p /work
tar -C /src --exclude=./target --exclude=./.git -cf - . | tar -C /work -xf -
cd /work

echo "── cargo build --release --locked ──"
cargo build --release --locked 2>&1 | tail -5
echo

# Phase 2: flip system DNS to numa itself — this is the pathological
# topology from issue #122 (HAOS add-on, resolv.conf → 127.0.0.1).
# Everything after this point, any getaddrinfo call inside numa loops
# back through :53.
echo "nameserver 127.0.0.1" > /etc/resolv.conf
echo "── /etc/resolv.conf inside container (post-flip) ──"
cat /etc/resolv.conf
echo

cat > /tmp/numa.toml <<CONF
[server]
bind_addr = "0.0.0.0:53"
api_port = 5380
api_bind_addr = "127.0.0.1"
data_dir = "/tmp/numa-data"

[upstream]
mode = "forward"
address = ["https://dns.quad9.net/dns-query"]
timeout_ms = 3000

[blocking]
enabled = true
lists = ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro.txt"]
CONF

mkdir -p /tmp/numa-data

echo "── starting numa ──"
RUST_LOG=info ./target/release/numa /tmp/numa.toml > /tmp/numa.log 2>&1 &
NUMA_PID=$!

# Wait up to 120s for blocklist to populate.
# Retry delays 2+10+30s = 42s, plus ~4 × ~10s getaddrinfo timeouts under
# self-loop = ~82s worst case. 120s leaves headroom.
LOADED=0
for i in $(seq 1 120); do
    LOADED=$(curl -sf http://127.0.0.1:5380/blocking/stats 2>/dev/null \
        | grep -o "\"domains_loaded\":[0-9]*" | cut -d: -f2 || echo 0)
    [ "${LOADED:-0}" -gt 100 ] && break
    sleep 1
done

# First cold DoH query — time it.
START=$(date +%s%N)
dig @127.0.0.1 example.com A +time=15 +tries=1 > /tmp/dig.out 2>&1 || true
END=$(date +%s%N)
LATENCY_MS=$(( (END - START) / 1000000 ))
STATUS=$(grep -oE "status: [A-Z]+" /tmp/dig.out | head -1 || echo "status: TIMEOUT")

kill $NUMA_PID 2>/dev/null || true
wait $NUMA_PID 2>/dev/null || true

echo
echo "=== RESULT ==="
echo "domains_loaded=$LOADED"
echo "first_query_latency_ms=$LATENCY_MS"
echo "first_query_${STATUS// /_}"
echo
echo "=== numa.log (tail 40) ==="
tail -40 /tmp/numa.log
echo
echo "=== dig.out ==="
cat /tmp/dig.out
' 2>&1 | tee "$OUT"

echo
echo "── assertions ──"

LOADED=$(grep '^domains_loaded=' "$OUT" | tail -1 | cut -d= -f2 || echo 0)
LATENCY=$(grep '^first_query_latency_ms=' "$OUT" | tail -1 | cut -d= -f2 || echo 999999)
STATUS_LINE=$(grep '^first_query_status_' "$OUT" | tail -1 || echo "first_query_status_TIMEOUT")

if [ "${LOADED:-0}" -gt 100 ]; then
    pass "blocklist downloaded (domains_loaded=$LOADED)"
else
    fail "blocklist downloaded (got domains_loaded=${LOADED:-0}, expected >100)" \
         "chicken-and-egg: blocklist HTTPS client has no DNS bootstrap; getaddrinfo loops through numa"
fi

if [ "${LATENCY:-999999}" -lt 2000 ]; then
    pass "first DoH query under 2s (latency=${LATENCY}ms, $STATUS_LINE)"
else
    fail "first DoH query under 2s (got ${LATENCY}ms, $STATUS_LINE)" \
         "self-loop on getaddrinfo(upstream_host); plain DoH needs bootstrap-IP symmetry with ODoH"
fi

echo
if [ "$FAILED" -eq 0 ]; then
    printf "${GREEN}── self-resolver-loop passed (fix is in place) ──${RESET}\n"
    exit 0
else
    printf "${RED}── self-resolver-loop failed ($FAILED assertion(s)) — bug #122 reproduced ──${RESET}\n"
    exit 1
fi
