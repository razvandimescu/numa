#!/usr/bin/env bash
# Network probe: tests which DNS transports are available on the current network.
# Run on a problematic network to diagnose what's blocked.
# Usage: ./tests/network-probe.sh

set -euo pipefail

GREEN="\033[32m"
RED="\033[31m"
DIM="\033[90m"
RESET="\033[0m"

PASSED=0
FAILED=0

probe() {
    local name="$1"
    local cmd="$2"
    local expect="$3"

    local result
    result=$(eval "$cmd" 2>&1) || true

    if echo "$result" | grep -q "$expect"; then
        PASSED=$((PASSED + 1))
        printf "  ${GREEN}✓${RESET} %-45s ${DIM}%s${RESET}\n" "$name" "$(echo "$result" | head -1 | cut -c1-60)"
    else
        FAILED=$((FAILED + 1))
        printf "  ${RED}✗${RESET} %-45s ${DIM}blocked/timeout${RESET}\n" "$name"
    fi
}

echo ""
echo "Network DNS Transport Probe"
echo "==========================="
echo "Network: $(networksetup -getairportnetwork en0 2>/dev/null | sed 's/Current Wi-Fi Network: //' || echo 'unknown')"
echo "Local IP: $(ipconfig getifaddr en0 2>/dev/null || echo 'unknown')"
echo "Gateway:  $(route -n get default 2>/dev/null | grep gateway | awk '{print $2}' || echo 'unknown')"
echo ""

echo "=== UDP port 53 (recursive resolution) ==="
probe "Root server a (198.41.0.4)" \
    "dig @198.41.0.4 . NS +short +time=5 +tries=1" \
    "root-servers"

probe "Root server k (193.0.14.129)" \
    "dig @193.0.14.129 . NS +short +time=5 +tries=1" \
    "root-servers"

probe "Google DNS (8.8.8.8)" \
    "dig @8.8.8.8 google.com A +short +time=5 +tries=1" \
    "\."

probe "Cloudflare (1.1.1.1)" \
    "dig @1.1.1.1 cloudflare.com A +short +time=5 +tries=1" \
    "\."

probe ".com TLD (192.5.6.30)" \
    "dig @192.5.6.30 google.com NS +short +time=5 +tries=1" \
    "google"

echo ""
echo "=== TCP port 53 ==="
probe "Google DNS TCP (8.8.8.8)" \
    "dig @8.8.8.8 google.com A +short +tcp +time=5 +tries=1" \
    "\."

probe "Root server TCP (198.41.0.4)" \
    "dig @198.41.0.4 . NS +short +tcp +time=5 +tries=1" \
    "root-servers"

echo ""
echo "=== DoT port 853 (DNS-over-TLS) ==="
probe "Quad9 DoT (9.9.9.9:853)" \
    "echo Q | openssl s_client -connect 9.9.9.9:853 -servername dns.quad9.net 2>&1 | grep 'verify return'" \
    "verify return"

probe "Cloudflare DoT (1.1.1.1:853)" \
    "echo Q | openssl s_client -connect 1.1.1.1:853 -servername cloudflare-dns.com 2>&1 | grep 'verify return'" \
    "verify return"

echo ""
echo "=== DoH port 443 (DNS-over-HTTPS) ==="
probe "Quad9 DoH (dns.quad9.net)" \
    "curl -s -m 5 -H 'accept: application/dns-json' 'https://dns.quad9.net:443/dns-query?name=google.com&type=A'" \
    "Answer"

probe "Cloudflare DoH (1.1.1.1)" \
    "curl -s -m 5 -H 'accept: application/dns-json' 'https://1.1.1.1/dns-query?name=google.com&type=A'" \
    "Answer"

probe "Google DoH (dns.google)" \
    "curl -s -m 5 'https://dns.google/resolve?name=google.com&type=A'" \
    "Answer"

echo ""
echo "=== ISP DNS ==="
# Detect system DNS
SYS_DNS=$(scutil --dns 2>/dev/null | grep "nameserver\[0\]" | head -1 | awk '{print $3}' || echo "unknown")
if [ "$SYS_DNS" != "unknown" ] && [ "$SYS_DNS" != "127.0.0.1" ]; then
    probe "ISP DNS ($SYS_DNS)" \
        "dig @$SYS_DNS google.com A +short +time=5 +tries=1" \
        "\."
else
    printf "  ${DIM}– System DNS is $SYS_DNS (skipped)${RESET}\n"
fi

echo ""
echo "==========================="
TOTAL=$((PASSED + FAILED))
printf "Results: ${GREEN}%d passed${RESET}, ${RED}%d blocked${RESET} / %d total\n" "$PASSED" "$FAILED" "$TOTAL"

echo ""
echo "Recommendation:"
if [ "$FAILED" -eq 0 ]; then
    echo "  All transports available. Recursive mode will work."
elif dig @198.41.0.4 . NS +short +time=5 +tries=1 2>&1 | grep -q "root-servers"; then
    echo "  UDP:53 works. Recursive mode will work."
else
    echo "  UDP:53 blocked — recursive mode will NOT work on this network."
    if curl -s -m 5 'https://dns.quad9.net:443/dns-query?name=test.com&type=A' 2>&1 | grep -q "Answer"; then
        echo "  DoH (port 443) works — use mode = \"forward\" with DoH upstream."
    elif echo Q | openssl s_client -connect 9.9.9.9:853 2>&1 | grep -q "verify return"; then
        echo "  DoT (port 853) works — DoT upstream would work (not yet implemented)."
    else
        echo "  Only ISP DNS available. Use mode = \"forward\" with ISP auto-detect."
    fi
fi
