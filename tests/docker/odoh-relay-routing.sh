#!/usr/bin/env bash
# Relay-side half of issue #365: every path that is not exactly `/relay`
# used to die on Caddy's empty-bodied 404, before the relay could say what
# the endpoint was — and the relay keeps no request logs to consult instead.
#
# Runs the shipped routing rules (packaging/relay/Caddyfile, rewritten only
# for the site address and upstream) in front of a `numa relay` on the host:
#
#   curl → Caddy :8081 (docker) → host.docker.internal:8443 (numa relay)
#
# Hermetic: the forward leg points at a host that cannot resolve, so a 502
# proves the request reached the relay without needing a live ODoH target.
#
# Usage:
#   tests/docker/odoh-relay-routing.sh
#   NUMA_BIN=./target/release/numa tests/docker/odoh-relay-routing.sh

set -euo pipefail

NUMA_BIN="${NUMA_BIN:-./target/debug/numa}"
CADDY_PORT="${CADDY_PORT:-8081}"
RELAY_PORT=8443
CADDYFILE="$(cd "$(dirname "$0")" && pwd)/Caddyfile.local"
CONTAINER=numa-odoh-relay-routing
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RELAY_PID=""
FAILED=0

GREEN=$'\033[32m'
RED=$'\033[31m'
DIM=$'\033[90m'
RESET=$'\033[0m'

cleanup() {
    if [ -n "$RELAY_PID" ]; then
        kill "$RELAY_PID" 2>/dev/null || true
        wait "$RELAY_PID" 2>/dev/null || true
    fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -f "$CADDYFILE"
}
trap cleanup EXIT

if [ ! -x "$NUMA_BIN" ]; then
    echo "${RED}✗${RESET} numa binary not found at $NUMA_BIN — run 'cargo build' first"
    exit 2
fi

sed -e 's|^odoh-relay\.example\.com {|:8081 {|' \
    -e "s|numa-relay:8443|host.docker.internal:${RELAY_PORT}|" \
    "$ROOT/packaging/relay/Caddyfile" > "$CADDYFILE"

echo "${DIM}Starting numa relay on 127.0.0.1:${RELAY_PORT}...${RESET}"
"$NUMA_BIN" relay "$RELAY_PORT" 127.0.0.1 >/dev/null 2>&1 &
RELAY_PID=$!
sleep 1

# Plain HTTP: numa's ODoH client pins the Mozilla roots, so a locally issued
# cert would be unusable by it anyway, and routing is what this checks. Run on
# the default bridge — a dedicated network buys nothing for one container and
# fails outright on a host whose address pools are already subnetted.
echo "${DIM}Starting Caddy on 127.0.0.1:${CADDY_PORT}...${RESET}"
docker run -d --rm --name "$CONTAINER" \
    -p "127.0.0.1:${CADDY_PORT}:8081" \
    --add-host "host.docker.internal:host-gateway" \
    -v "$CADDYFILE:/etc/caddy/Caddyfile:ro" \
    caddy:2 >/dev/null
sleep 2

# method path expected_status expected_body_substring
check() {
    local method="$1" path="$2" want_status="$3" want_body="$4"
    local body status
    body=$(curl -s --max-time 8 -o /dev/stdout -w '\n%{http_code}' -X "$method" \
        -H 'content-type: application/oblivious-dns-message' \
        --data-binary 'probe' "http://127.0.0.1:${CADDY_PORT}${path}" || true)
    status="${body##*$'\n'}"
    body="${body%$'\n'*}"

    if [ "$status" = "$want_status" ] && [[ "$body" == *"$want_body"* ]]; then
        printf '  %s✓%s %-6s %-46s %s\n' "$GREEN" "$RESET" "$method" "$path" "$status"
    else
        printf '  %s✗%s %-6s %-46s got %s want %s%s\n' "$RED" "$RESET" "$method" "$path" \
            "$status" "$want_status" "${want_body:+ / body '$want_body'}"
        printf '      %sbody: %s%s\n' "$DIM" "${body:-<empty>}" "$RESET"
        FAILED=1
    fi
}

FORWARD='?targethost=unreachable.invalid&targetpath=/dns-query'

echo "── routing ─────────────────────────────────────────────────────────"
# 502 means the relay accepted the route and tried the forward leg.
check POST "/relay${FORWARD}"  502 "target unreachable"
check POST "/relay/${FORWARD}" 502 "target unreachable"
check POST "/nope"             404 "numa ODoH relay: POST /relay"
check POST "/relay"            400 "targethost"
check GET  "/health"           200 "forwarded_ok"

if [ "$FAILED" -eq 0 ]; then
    echo "${GREEN}✓${RESET} every path is answered by the relay, with a body that names the cause"
else
    echo "${RED}✗${RESET} routing regressions above"
fi
exit "$FAILED"
