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

echo ""
echo "=== TCP wire format (real servers) ==="

# Microsoft's Azure DNS servers require length+message in a single TCP segment.
# This test catches the split-write bug that caused early-eof SERVFAILs.
check "Microsoft domain (update.code.visualstudio.com)" \
    "NOERROR" \
    "$($DIG update.code.visualstudio.com A 2>&1 | grep status:)"

check "Office domain (ecs.office.com)" \
    "NOERROR" \
    "$($DIG ecs.office.com A 2>&1 | grep status:)"

# Azure Application Insights — another strict TCP server
check "Azure telemetry (eastus2-3.in.applicationinsights.azure.com)" \
    "." \
    "$($DIG eastus2-3.in.applicationinsights.azure.com A +short 2>/dev/null || echo 'timeout')"

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
sleep 1

# ---- Suite 5: DNS-over-TLS (RFC 7858) ----
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Suite 5: DNS-over-TLS (RFC 7858)        ║"
echo "╚══════════════════════════════════════════╝"

if ! command -v kdig >/dev/null 2>&1; then
    printf "  ${DIM}skipped — install 'knot' for kdig${RESET}\n"
elif ! command -v openssl >/dev/null 2>&1; then
    printf "  ${DIM}skipped — openssl not found${RESET}\n"
else
    DOT_PORT=8853
    DOT_CERT=/tmp/numa-integration-dot.crt
    DOT_KEY=/tmp/numa-integration-dot.key

    # Generate a test cert mirroring production self_signed_tls SAN shape
    # (*.numa wildcard + explicit numa.numa apex).
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -keyout "$DOT_KEY" -out "$DOT_CERT" \
        -subj "/CN=Numa .numa services" \
        -addext "subjectAltName=DNS:*.numa,DNS:numa.numa" \
        >/dev/null 2>&1

    # Suite 5 uses a local zone so it's upstream-independent — the point is
    # to exercise the DoT transport layer (handshake, ALPN, framing,
    # persistent connections), not re-test recursive resolution.
    cat > "$CONFIG" << CONF
[server]
bind_addr = "127.0.0.1:$PORT"
api_port = $API_PORT

[upstream]
mode = "forward"
address = "127.0.0.1"
port = 65535

[cache]
max_entries = 10000

[blocking]
enabled = false

[proxy]
enabled = false

[dot]
enabled = true
port = $DOT_PORT
bind_addr = "127.0.0.1"
cert_path = "$DOT_CERT"
key_path = "$DOT_KEY"

[[zones]]
domain = "dot-test.example"
record_type = "A"
value = "10.0.0.1"
ttl = 60
CONF

    RUST_LOG=info "$BINARY" "$CONFIG" > "$LOG" 2>&1 &
    NUMA_PID=$!
    sleep 4

    if ! kill -0 "$NUMA_PID" 2>/dev/null; then
        FAILED=$((FAILED + 1))
        printf "  ${RED}✗${RESET} DoT startup\n"
        printf "    ${DIM}%s${RESET}\n" "$(tail -5 "$LOG")"
    else
        echo ""
        echo "=== Listener ==="

        check "DoT bound on 127.0.0.1:$DOT_PORT" \
            "DoT listening on 127.0.0.1:$DOT_PORT" \
            "$(grep 'DoT listening' "$LOG")"

        KDIG="kdig @127.0.0.1 -p $DOT_PORT +tls +tls-ca=$DOT_CERT +tls-hostname=numa.numa +time=5 +retry=0"

        echo ""
        echo "=== Queries over DoT ==="

        check "DoT local zone A record" \
            "10.0.0.1" \
            "$($KDIG +short dot-test.example A 2>/dev/null)"

        # +keepopen reuses one TLS connection for multiple queries — tests
        # persistent connection handling. kdig applies options left-to-right,
        # so +short and +keepopen must come before the query specs.
        check "DoT persistent connection (3 queries, 1 handshake)" \
            "10.0.0.1" \
            "$($KDIG +keepopen +short dot-test.example A dot-test.example A dot-test.example A 2>/dev/null | head -1)"

        echo ""
        echo "=== ALPN ==="

        # Positive case: client offers "dot", server picks it.
        ALPN_OK=$(echo "" | openssl s_client -connect "127.0.0.1:$DOT_PORT" \
            -servername numa.numa -alpn dot -CAfile "$DOT_CERT" 2>&1 </dev/null || true)
        check "DoT negotiates ALPN \"dot\"" \
            "ALPN protocol: dot" \
            "$ALPN_OK"

        # Negative case: client offers only "h2", server must reject the
        # handshake with no_application_protocol alert (cross-protocol
        # confusion defense, RFC 7858bis §3.2).
        if echo "" | openssl s_client -connect "127.0.0.1:$DOT_PORT" \
            -servername numa.numa -alpn h2 -CAfile "$DOT_CERT" \
            </dev/null >/dev/null 2>&1; then
            ALPN_MISMATCH="handshake unexpectedly succeeded"
        else
            ALPN_MISMATCH="rejected"
        fi
        check "DoT rejects non-dot ALPN" \
            "rejected" \
            "$ALPN_MISMATCH"
    fi

    kill "$NUMA_PID" 2>/dev/null || true
    wait "$NUMA_PID" 2>/dev/null || true
    rm -f "$DOT_CERT" "$DOT_KEY"
fi
sleep 1

# ---- Suite 6: Proxy + DoT coexistence ----
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Suite 6: Proxy + DoT Coexistence        ║"
echo "╚══════════════════════════════════════════╝"

if ! command -v kdig >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    printf "  ${DIM}skipped — needs kdig + openssl${RESET}\n"
else
    DOT_PORT=8853
    PROXY_HTTP_PORT=8080
    PROXY_HTTPS_PORT=8443
    NUMA_DATA=/tmp/numa-integration-data

    # Fresh data dir so we generate a fresh CA for this suite — NUMA_DATA_DIR
    # env var lets numa write under $TMPDIR instead of /usr/local/var/numa.
    rm -rf "$NUMA_DATA"
    mkdir -p "$NUMA_DATA"

    cat > "$CONFIG" << CONF
[server]
bind_addr = "127.0.0.1:$PORT"
api_port = $API_PORT

[upstream]
mode = "forward"
address = "127.0.0.1"
port = 65535

[cache]
max_entries = 10000

[blocking]
enabled = false

[proxy]
enabled = true
port = $PROXY_HTTP_PORT
tls_port = $PROXY_HTTPS_PORT
tld = "numa"
bind_addr = "127.0.0.1"

[dot]
enabled = true
port = $DOT_PORT
bind_addr = "127.0.0.1"

[[zones]]
domain = "dot-test.example"
record_type = "A"
value = "10.0.0.1"
ttl = 60
CONF

    NUMA_DATA_DIR="$NUMA_DATA" RUST_LOG=info "$BINARY" "$CONFIG" > "$LOG" 2>&1 &
    NUMA_PID=$!
    sleep 4

    if ! kill -0 "$NUMA_PID" 2>/dev/null; then
        FAILED=$((FAILED + 1))
        printf "  ${RED}✗${RESET} Startup with proxy + DoT\n"
        printf "    ${DIM}%s${RESET}\n" "$(tail -5 "$LOG")"
    else
        echo ""
        echo "=== Both listeners ==="

        check "DoT listener bound" \
            "DoT listening on 127.0.0.1:$DOT_PORT" \
            "$(grep 'DoT listening' "$LOG")"

        check "HTTPS proxy listener bound" \
            "HTTPS proxy listening on 127.0.0.1:$PROXY_HTTPS_PORT" \
            "$(grep 'HTTPS proxy listening' "$LOG")"

        PANIC_COUNT=$(grep -c 'panicked' "$LOG" 2>/dev/null || echo 0)
        check "No startup panics in log" \
            "^0$" \
            "$PANIC_COUNT"

        echo ""
        echo "=== DoT works with proxy enabled ==="

        # Proxy's build_tls_config runs first and creates the CA in
        # $NUMA_DATA_DIR. DoT self_signed_tls then loads the same CA and
        # issues its own leaf cert. One CA trusts both listeners.
        CA="$NUMA_DATA/ca.pem"
        KDIG="kdig @127.0.0.1 -p $DOT_PORT +tls +tls-ca=$CA +tls-hostname=numa.numa +time=5 +retry=0"

        check "DoT local zone A (with proxy on)" \
            "10.0.0.1" \
            "$($KDIG +short dot-test.example A 2>/dev/null)"

        echo ""
        echo "=== Proxy TLS works with DoT enabled ==="

        # Proxy cert has SAN numa.numa (auto-added "numa" service). A
        # successful handshake validates that the proxy's separate
        # ServerConfig wasn't disturbed by DoT's own cert generation.
        PROXY_TLS=$(echo "" | openssl s_client -connect "127.0.0.1:$PROXY_HTTPS_PORT" \
            -servername numa.numa -CAfile "$CA" 2>&1 </dev/null || true)
        check "Proxy HTTPS TLS handshake succeeds" \
            "Verify return code: 0 (ok)" \
            "$PROXY_TLS"
    fi

    kill "$NUMA_PID" 2>/dev/null || true
    wait "$NUMA_PID" 2>/dev/null || true
    rm -rf "$NUMA_DATA"
fi

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
