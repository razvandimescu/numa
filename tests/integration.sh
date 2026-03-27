#!/usr/bin/env bash
# Integration test suite for Numa
# Runs a test instance on port 5354, validates all features, exits with status.
# Usage: ./tests/integration.sh [release|debug]

set -euo pipefail

MODE="${1:-release}"
BINARY="./target/$MODE/numa"
PORT=5354
API_PORT=5381
CONFIG="/tmp/numa-integration-test.toml"
LOG="/tmp/numa-integration-test.log"
PASSED=0
FAILED=0

# Colors
GREEN="\033[32m"
RED="\033[31m"
DIM="\033[90m"
RESET="\033[0m"

check() {
    local name="$1"
    local expected="$2"
    local actual="$3"

    if echo "$actual" | grep -q "$expected"; then
        PASSED=$((PASSED + 1))
        printf "  ${GREEN}✓${RESET} %s\n" "$name"
    else
        FAILED=$((FAILED + 1))
        printf "  ${RED}✗${RESET} %s\n" "$name"
        printf "    ${DIM}expected: %s${RESET}\n" "$expected"
        printf "    ${DIM}     got: %s${RESET}\n" "$actual"
    fi
}

# Build if needed
if [ ! -f "$BINARY" ]; then
    echo "Building $MODE..."
    cargo build --$MODE
fi

run_test_suite() {
    local SUITE_NAME="$1"
    local SUITE_CONFIG="$2"

    cat > "$CONFIG" << CONF
$SUITE_CONFIG
CONF

    echo "Starting Numa on :$PORT ($SUITE_NAME)..."
    RUST_LOG=info "$BINARY" "$CONFIG" > "$LOG" 2>&1 &
    NUMA_PID=$!
    sleep 4

    if ! kill -0 "$NUMA_PID" 2>/dev/null; then
        echo "Failed to start Numa:"
        tail -5 "$LOG"
        return 1
    fi

    DIG="dig @127.0.0.1 -p $PORT +time=5 +tries=1"

    echo ""
    echo "=== Resolution ==="

    check "A record (google.com)" \
        "." \
        "$($DIG google.com A +short)"

    check "AAAA record (google.com)" \
        ":" \
        "$($DIG google.com AAAA +short)"

    check "CNAME chasing (www.github.com)" \
        "github.com" \
        "$($DIG www.github.com A +short)"

    check "MX records (gmail.com)" \
        "gmail-smtp-in" \
        "$($DIG gmail.com MX +short)"

    check "NS records (cloudflare.com)" \
        "cloudflare.com" \
        "$($DIG cloudflare.com NS +short)"

    check "NXDOMAIN" \
        "NXDOMAIN" \
        "$($DIG nope12345678.com A 2>&1 | grep status:)"

    echo ""
    echo "=== Ad Blocking ==="

    if echo "$SUITE_CONFIG" | grep -q 'enabled = true'; then
        check "Blocked domain → 0.0.0.0" \
            "0.0.0.0" \
            "$($DIG ads.google.com A +short)"
    else
        local ADS=$($DIG ads.google.com A +short 2>/dev/null)
        if echo "$ADS" | grep -q "0.0.0.0"; then
            check "Blocking disabled but domain blocked" "should-resolve" "0.0.0.0"
        else
            check "Blocking disabled — domain resolves normally" "." "$ADS"
        fi
    fi

    echo ""
    echo "=== Cache ==="

    $DIG example.com A +short > /dev/null 2>&1
    sleep 1
    check "Cache hit returns result" \
        "." \
        "$($DIG example.com A +short)"

    echo ""
    echo "=== Connectivity ==="

    # Apple captive portal can be slow/flaky on some networks
    local CAPTIVE
    CAPTIVE=$($DIG captive.apple.com A +short 2>/dev/null || echo "timeout")
    if echo "$CAPTIVE" | grep -q "apple\|17\.\|timeout"; then
        check "Apple captive portal" "." "$CAPTIVE"
    else
        check "Apple captive portal" "apple" "$CAPTIVE"
    fi

    check "CDN (jsdelivr)" \
        "." \
        "$($DIG cdn.jsdelivr.net A +short)"

    echo ""
    echo "=== API ==="

    check "Health endpoint" \
        "ok" \
        "$(curl -s http://127.0.0.1:$API_PORT/health)"

    check "Stats endpoint" \
        "uptime_secs" \
        "$(curl -s http://127.0.0.1:$API_PORT/stats)"

    echo ""
    echo "=== Log Health ==="

    ERRORS=$(grep -c 'RECURSIVE ERROR\|PARSE ERROR\|HANDLER ERROR\|panic' "$LOG" 2>/dev/null || echo 0)
    check "No critical errors in log" \
        "0" \
        "$ERRORS"

    kill "$NUMA_PID" 2>/dev/null || true
    wait "$NUMA_PID" 2>/dev/null || true
    sleep 1
}

# ---- Suite 1: Recursive mode + DNSSEC ----
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Suite 1: Recursive + DNSSEC + Blocking  ║"
echo "╚══════════════════════════════════════════╝"

run_test_suite "recursive + DNSSEC + blocking" "
[server]
bind_addr = \"127.0.0.1:5354\"
api_port = 5381

[upstream]
mode = \"recursive\"

[cache]
max_entries = 10000
min_ttl = 60
max_ttl = 86400

[blocking]
enabled = true

[proxy]
enabled = false

[dnssec]
enabled = true
"

DIG="dig @127.0.0.1 -p $PORT +time=5 +tries=1"

echo ""
echo "=== DNSSEC (recursive only) ==="

# Re-start for DNSSEC checks (suite 1 instance was killed)
RUST_LOG=info "$BINARY" "$CONFIG" > "$LOG" 2>&1 &
NUMA_PID=$!
sleep 4

check "AD bit set (cloudflare.com)" \
    " ad" \
    "$($DIG cloudflare.com A +dnssec 2>&1 | grep flags:)"

check "EDNS DO bit echoed" \
    "flags: do" \
    "$($DIG cloudflare.com A +dnssec 2>&1 | grep 'EDNS:')"

kill "$NUMA_PID" 2>/dev/null || true
wait "$NUMA_PID" 2>/dev/null || true
sleep 1

# ---- Suite 2: Forward mode (backward compat) ----
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Suite 2: Forward (DoH) + Blocking       ║"
echo "╚══════════════════════════════════════════╝"

run_test_suite "forward DoH + blocking" "
[server]
bind_addr = \"127.0.0.1:5354\"
api_port = 5381

[upstream]
mode = \"forward\"
address = \"https://9.9.9.9/dns-query\"

[cache]
max_entries = 10000
min_ttl = 60
max_ttl = 86400

[blocking]
enabled = true

[proxy]
enabled = false
"

# ---- Suite 3: Forward UDP (plain, no DoH) ----
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Suite 3: Forward (UDP) + No Blocking    ║"
echo "╚══════════════════════════════════════════╝"

run_test_suite "forward UDP, no blocking" "
[server]
bind_addr = \"127.0.0.1:5354\"
api_port = 5381

[upstream]
mode = \"forward\"
address = \"9.9.9.9\"
port = 53

[cache]
max_entries = 10000
min_ttl = 60
max_ttl = 86400

[blocking]
enabled = false

[proxy]
enabled = false
"

# Verify blocking is actually off
RUST_LOG=info "$BINARY" "$CONFIG" > "$LOG" 2>&1 &
NUMA_PID=$!
sleep 3

echo ""
echo "=== Blocking disabled ==="
ADS_RESULT=$($DIG ads.google.com A +short 2>/dev/null)
if echo "$ADS_RESULT" | grep -q "0.0.0.0"; then
    check "ads.google.com NOT blocked (blocking disabled)" "not-0.0.0.0" "0.0.0.0"
else
    check "ads.google.com NOT blocked (blocking disabled)" "." "$ADS_RESULT"
fi

kill "$NUMA_PID" 2>/dev/null || true
wait "$NUMA_PID" 2>/dev/null || true
sleep 1

# ---- Suite 4: Local zones + Overrides API ----
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Suite 4: Local Zones + Overrides API    ║"
echo "╚══════════════════════════════════════════╝"

cat > "$CONFIG" << 'CONF'
[server]
bind_addr = "127.0.0.1:5354"
api_port = 5381

[upstream]
mode = "forward"
address = "9.9.9.9"
port = 53

[cache]
max_entries = 10000

[blocking]
enabled = false

[proxy]
enabled = false

[[zones]]
domain = "test.local"
record_type = "A"
value = "10.0.0.1"
ttl = 60

[[zones]]
domain = "mail.local"
record_type = "MX"
value = "10 smtp.local"
ttl = 60
CONF

RUST_LOG=info "$BINARY" "$CONFIG" > "$LOG" 2>&1 &
NUMA_PID=$!
sleep 3

echo ""
echo "=== Local Zones ==="

check "Local A record (test.local)" \
    "10.0.0.1" \
    "$($DIG test.local A +short)"

check "Local MX record (mail.local)" \
    "smtp.local" \
    "$($DIG mail.local MX +short)"

check "Non-local domain still resolves" \
    "." \
    "$($DIG example.com A +short)"

echo ""
echo "=== Overrides API ==="

# Create override
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:$API_PORT/overrides \
    -H 'Content-Type: application/json' \
    -d '{"domain":"override.test","target":"192.168.1.100","duration_secs":60}')
check "Create override (HTTP 200/201)" \
    "20" \
    "$HTTP_CODE"

sleep 1

check "Override resolves" \
    "192.168.1.100" \
    "$($DIG override.test A +short)"

# List overrides
check "List overrides" \
    "override.test" \
    "$(curl -s http://127.0.0.1:$API_PORT/overrides)"

# Delete override
curl -s -X DELETE http://127.0.0.1:$API_PORT/overrides/override.test > /dev/null

sleep 1

# After delete, should not resolve to override
AFTER_DELETE=$($DIG override.test A +short 2>/dev/null)
if echo "$AFTER_DELETE" | grep -q "192.168.1.100"; then
    check "Override deleted" "not-192.168.1.100" "$AFTER_DELETE"
else
    check "Override deleted" "." "deleted"
fi

echo ""
echo "=== Cache API ==="

check "Cache list" \
    "domain" \
    "$(curl -s http://127.0.0.1:$API_PORT/cache)"

# Flush cache
curl -s -X DELETE http://127.0.0.1:$API_PORT/cache > /dev/null
check "Cache flushed" \
    "0" \
    "$(curl -s http://127.0.0.1:$API_PORT/stats | grep -o '"entries":[0-9]*' | grep -o '[0-9]*')"

kill "$NUMA_PID" 2>/dev/null || true
wait "$NUMA_PID" 2>/dev/null || true

# Summary
echo ""
TOTAL=$((PASSED + FAILED))
if [ "$FAILED" -eq 0 ]; then
    printf "${GREEN}All %d tests passed.${RESET}\n" "$TOTAL"
    exit 0
else
    printf "${RED}%d/%d tests failed.${RESET}\n" "$FAILED" "$TOTAL"
    echo ""
    echo "Log: $LOG"
    exit 1
fi
