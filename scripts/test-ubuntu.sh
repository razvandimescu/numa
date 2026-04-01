#!/bin/bash
# Ubuntu integration test for Numa PR #27
# Usage: scp target/release/numa scripts/test-ubuntu.sh EC2:~ && ssh EC2 'sudo bash test-ubuntu.sh'
set -euo pipefail

BIN="./numa"
PASS=0
FAIL=0

check() {
    local desc="$1"; shift
    if "$@" > /dev/null 2>&1; then
        echo "  ✓ $desc"
        PASS=$((PASS + 1))
    else
        echo "  ✗ $desc"
        FAIL=$((FAIL + 1))
    fi
}

cleanup() {
    $BIN uninstall 2>/dev/null || true
    killall numa 2>/dev/null || true
    sleep 1
}

echo "=== Numa Ubuntu Integration Tests ==="
echo ""
chmod +x "$BIN"

# --- Test 1: Forward mode (default, no config) ---
echo "--- Test 1: Forward mode (default) ---"
cleanup
$BIN 2>&1 &
NUMA_PID=$!
sleep 3

check "API responds" curl -sf http://127.0.0.1:5380/health
check "mode is forward" bash -c 'curl -sf http://127.0.0.1:5380/stats | grep -q "\"mode\":\"forward\""'
check "DNS resolves" bash -c 'dig @127.0.0.1 example.com A +short +time=5 | grep -q "[0-9]"'
check "dashboard returns 200" bash -c 'curl -sf -o /dev/null -w "%{http_code}" http://127.0.0.1:5380/ | grep -q 200'
kill $NUMA_PID 2>/dev/null; sleep 1
echo ""

# --- Test 2: Recursive mode (explicit opt-in) ---
echo "--- Test 2: Recursive mode ---"
cleanup
mkdir -p /tmp/numa-test
cat > /tmp/numa-test/numa.toml << 'TOML'
[upstream]
mode = "recursive"
[dnssec]
enabled = true
TOML
$BIN /tmp/numa-test/numa.toml 2>&1 &
NUMA_PID=$!
sleep 5

check "API responds" curl -sf http://127.0.0.1:5380/health
check "mode is recursive" bash -c 'curl -sf http://127.0.0.1:5380/stats | grep -q "\"mode\":\"recursive\""'
check "dnssec enabled" bash -c 'curl -sf http://127.0.0.1:5380/stats | grep -q "\"dnssec\":true"'
check "DNS resolves recursively" bash -c 'dig @127.0.0.1 example.com A +short +time=10 | grep -q "[0-9]"'
check "AD flag set (DNSSEC)" bash -c 'dig @127.0.0.1 example.com A +dnssec +time=10 | grep "flags:" | grep -q "ad"'
kill $NUMA_PID 2>/dev/null; sleep 1
echo ""

# --- Test 3: Auto mode ---
echo "--- Test 3: Auto mode ---"
cleanup
cat > /tmp/numa-test/numa.toml << 'TOML'
[upstream]
mode = "auto"
TOML
$BIN /tmp/numa-test/numa.toml 2>&1 &
NUMA_PID=$!
sleep 10

check "API responds" curl -sf http://127.0.0.1:5380/health
MODE=$(curl -sf http://127.0.0.1:5380/stats | python3 -c "import sys,json; print(json.load(sys.stdin)['mode'])" 2>/dev/null || echo "unknown")
echo "  → auto resolved to: $MODE"
check "mode is recursive or forward" bash -c "echo '$MODE' | grep -qE '^(recursive|forward)$'"
check "DNS resolves" bash -c 'dig @127.0.0.1 example.com A +short +time=10 | grep -q "[0-9]"'
kill $NUMA_PID 2>/dev/null; sleep 1
echo ""

# --- Test 4: Install / Uninstall ---
echo "--- Test 4: Install / Uninstall ---"
cleanup
cp "$BIN" /usr/local/bin/numa

echo "  Installing..."
INSTALL_OUTPUT=$($BIN install 2>&1) || true
echo "$INSTALL_OUTPUT"
check "post-install mentions recursive" bash -c "echo '$INSTALL_OUTPUT' | grep -q 'recursive'"
sleep 3

check "service is running" systemctl is-active numa
check "API responds after install" curl -sf http://127.0.0.1:5380/health
check "DNS resolves after install" bash -c 'dig @127.0.0.1 example.com A +short +time=5 | grep -q "[0-9]"'

echo ""
echo "  Uninstalling..."
$BIN uninstall 2>&1 || true
sleep 2

check "service stopped" bash -c '! systemctl is-active numa'
echo ""

# --- Test 5: Port 53 conflict ---
echo "--- Test 5: Port 53 conflict ---"
cleanup
# Start a dummy listener on port 53
python3 -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',53)); input()" &
BLOCKER_PID=$!
sleep 1

$BIN 2>&1 &
NUMA_PID=$!
sleep 3
# numa should fail to bind
check "numa fails when port 53 taken" bash -c '! kill -0 $NUMA_PID 2>/dev/null'
kill $BLOCKER_PID 2>/dev/null
kill $NUMA_PID 2>/dev/null
echo ""

# --- Cleanup ---
cleanup
rm -rf /tmp/numa-test

echo "=== Results: $PASS passed, $FAIL failed ==="
[ $FAIL -eq 0 ] && echo "All tests passed!" || echo "Some tests failed."
exit $FAIL
