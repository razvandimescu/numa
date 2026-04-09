#!/usr/bin/env bash
#
# Port-53 conflict advisory integration test.
#
# Builds numa from source inside a debian:bookworm container, pre-binds
# port 53 with a UDP socket, then runs numa bare (default bind_addr
# 0.0.0.0:53). Verifies:
#   - process exits with code 1
#   - stderr contains the advisory ("cannot bind to")
#   - stderr contains both fix suggestions ("numa install", "bind_addr")
#
# This is the end-to-end test for the fix in:
#   src/main.rs — AddrInUse match arm → eprint advisory + process::exit(1)
#
# No systemd-resolved needed — the conflict is simulated by a Python
# UDP socket held open before numa starts.
#
# Requirements: docker
# Usage:        ./tests/docker/smoke-port53.sh

set -euo pipefail

cd "$(dirname "$0")/../.."

GREEN="\033[32m"; RED="\033[31m"; RESET="\033[0m"

pass() { printf "  ${GREEN}✓${RESET} %s\n" "$1"; }
fail() { printf "  ${RED}✗${RESET} %s\n" "$1"; printf "    %s\n" "$2"; FAILED=$((FAILED+1)); }
FAILED=0

echo "── smoke-port53: building + testing numa on debian:bookworm ──"
echo "  (first run is slow: image pull + cold cargo build, ~5-8 min)"
echo

OUTPUT=$(docker run --rm \
    --platform linux/amd64 \
    -v "$PWD:/src:ro" \
    -v numa-port53-cargo:/root/.cargo \
    -v numa-port53-target:/work/target \
    debian:bookworm bash -c '
set -e

apt-get update -qq && apt-get install -y -qq curl build-essential python3 2>&1 | tail -3

# Install rustup if not already in the cargo cache volume
if ! command -v cargo &>/dev/null; then
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --quiet
fi
. "$HOME/.cargo/env"

# Copy source to a writable workdir
mkdir -p /work
tar -C /src --exclude=./target --exclude=./.git -cf - . | tar -C /work -xf -
cd /work

echo "── cargo build --release --locked ──"
cargo build --release --locked 2>&1 | tail -5
echo

# Write the holder script to a file to avoid quoting hell.
# Holds port 53 until killed — no sleep race.
cat > /tmp/hold53.py << '"'"'PYEOF'"'"'
import socket, signal
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
s.bind(("", 53))
signal.pause()
PYEOF

python3 /tmp/hold53.py &
HOLDER_PID=$!

# Verify the holder is actually up before proceeding
sleep 0.3
if ! kill -0 $HOLDER_PID 2>/dev/null; then
    echo "holder_failed=1"
    exit 1
fi

echo "── running numa with port 53 already bound ──"
# timeout 5: guards against numa not exiting (advisory not fired, bug present)
# Capture stderr to a file so the exit code is not clobbered by || or $()
set +e
timeout 5 ./target/release/numa > /tmp/numa-stderr.txt 2>&1
EXIT_CODE=$?
set -e
STDERR=$(cat /tmp/numa-stderr.txt)

kill $HOLDER_PID 2>/dev/null || true

echo "exit_code=$EXIT_CODE"
printf "%s" "$STDERR" | sed "s/^/  numa: /"
' 2>&1)

echo "$OUTPUT"

echo
echo "── assertions ──"

if echo "$OUTPUT" | grep -q "holder_failed=1"; then
    echo "  SETUP FAILED: could not pre-bind port 53 inside container"
    exit 1
fi

EXIT_CODE=$(echo "$OUTPUT" | grep '^exit_code=' | cut -d= -f2)

if [ "${EXIT_CODE:-}" = "1" ]; then
    pass "exits with code 1"
else
    fail "exits with code 1" "got: exit_code=${EXIT_CODE:-<missing>}"
fi

if echo "$OUTPUT" | grep -q "cannot bind to"; then
    pass "advisory printed to stderr"
else
    fail "advisory printed to stderr" "stderr did not contain 'cannot bind to'"
fi

if echo "$OUTPUT" | grep -q "numa install"; then
    pass "advisory offers 'sudo numa install'"
else
    fail "advisory offers 'sudo numa install'" "not found in output"
fi

if echo "$OUTPUT" | grep -q "bind_addr"; then
    pass "advisory offers non-privileged port alternative"
else
    fail "advisory offers non-privileged port alternative" "'bind_addr' not found in output"
fi

echo
if [ "$FAILED" -eq 0 ]; then
    printf "${GREEN}── smoke-port53 passed ──${RESET}\n"
    exit 0
else
    printf "${RED}── smoke-port53 failed ($FAILED assertion(s)) ──${RESET}\n"
    exit 1
fi
