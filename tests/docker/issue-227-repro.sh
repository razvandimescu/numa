#!/usr/bin/env bash
#
# Issue #227 — multi-homed wildcard bind reply-source bug.
#
# On a host with two IPs bound via 0.0.0.0, plain tokio::UdpSocket lets the
# kernel pick the reply source — typically the primary — so queries to the
# secondary IP get replies from the wrong source. Modern dig silently times
# out; older dig prints "reply from unexpected source".
#
# This script: inside a debian:bookworm container, adds 127.0.0.2 as a
# second lo address, binds numa to 0.0.0.0:5354, sends a UDP DNS query to
# each of {127.0.0.1, 127.0.0.2}, and asserts the reply source IP matches
# the destination IP.
#
# Requires: docker, --cap-add=NET_ADMIN for `ip addr add`.
# Usage:    ./tests/docker/issue-227-repro.sh

set -euo pipefail
cd "$(dirname "$0")/../.."

GREEN="\033[32m"; RED="\033[31m"; DIM="\033[90m"; RESET="\033[0m"
pass() { printf "  ${GREEN}✓${RESET} %s\n" "$1"; }
fail() { printf "  ${RED}✗${RESET} %s\n" "$1"; FAILED=$((FAILED+1)); }
FAILED=0

echo "── issue-227-repro: multi-homed wildcard bind on linux ──"
echo "  (first run: cold cargo build inside container, ~5-8 min)"
echo

OUTPUT=$(docker run --rm \
    --cap-add=NET_ADMIN \
    -v "$PWD:/src:ro" \
    -v numa-227-cargo:/root/.cargo \
    -v numa-227-target:/work/target \
    debian:bookworm bash -c '
set -e

apt-get update -qq && apt-get install -y -qq curl build-essential python3 iproute2 2>&1 | tail -3

if ! command -v cargo &>/dev/null; then
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --quiet
fi
. "$HOME/.cargo/env"

mkdir -p /work
tar -C /src --exclude=./target --exclude=./.git -cf - . | tar -C /work -xf -
cd /work

echo "── cargo build --release --locked ──"
cargo build --release --locked 2>&1 | tail -3
echo

ip addr add 127.0.0.2/8 dev lo
echo "── lo addresses ──"
ip -4 -o addr show lo | awk "{print \"  \" \$0}"
echo

mkdir -p /tmp/numa-data
cat > /tmp/numa.toml <<EOF
[server]
bind_addr = "0.0.0.0:5354"
api_port = 5382
data_dir = "/tmp/numa-data"

[upstream]
mode = "forward"
address = "9.9.9.9:53"
EOF

./target/release/numa /tmp/numa.toml >/tmp/numa.log 2>&1 &
NUMA_PID=$!

# Wait for numa to bind by polling port 5354.
for i in $(seq 1 20); do
    if ss -ulnH "( sport = :5354 )" 2>/dev/null | grep -q ":5354"; then
        break
    fi
    sleep 0.2
done
if ! kill -0 $NUMA_PID 2>/dev/null; then
    echo "numa failed to start:"
    tail -30 /tmp/numa.log
    exit 1
fi

cat > /tmp/probe.py <<"PYEOF"
import socket, struct, sys

def query(target_ip, port, qname="example.com."):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.bind(("0.0.0.0", 0))
    txid = 0x1234
    flags = 0x0100
    msg = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    for label in qname.split("."):
        if label:
            msg += bytes([len(label)]) + label.encode()
    msg += b"\x00" + struct.pack(">HH", 1, 1)
    s.sendto(msg, (target_ip, port))
    try:
        data, src = s.recvfrom(4096)
        rcode = data[3] & 0x0f
        return src[0], rcode, len(data)
    except socket.timeout:
        return None, None, 0

port = 5354
for ip in ["127.0.0.1", "127.0.0.2"]:
    src, rcode, n = query(ip, port)
    if src is None:
        print(f"RESULT sent_to={ip} reply_from=TIMEOUT")
    else:
        ok = "PASS" if src == ip else "FAIL"
        print(f"RESULT {ok} sent_to={ip} reply_from={src} rcode={rcode} bytes={n}")
PYEOF

python3 /tmp/probe.py

kill $NUMA_PID 2>/dev/null || true
wait $NUMA_PID 2>/dev/null || true

echo "── numa.log tail ──"
tail -10 /tmp/numa.log | sed "s/^/  /"
' 2>&1)

echo "$OUTPUT"
echo
echo "── assertions ──"

if echo "$OUTPUT" | grep -q "RESULT PASS sent_to=127.0.0.1"; then
    pass "127.0.0.1 query → reply from 127.0.0.1"
else
    fail "127.0.0.1 query → reply from 127.0.0.1"
fi

if echo "$OUTPUT" | grep -q "RESULT PASS sent_to=127.0.0.2"; then
    pass "127.0.0.2 query → reply from 127.0.0.2 (this is the #227 fix)"
else
    fail "127.0.0.2 query → reply from 127.0.0.2 (this is the #227 fix)"
fi

echo
if [ $FAILED -eq 0 ]; then
    printf "${GREEN}── issue-227-repro passed ──${RESET}\n"
    exit 0
fi
printf "${RED}── issue-227-repro failed (${FAILED} assertion(s)) ──${RESET}\n"
exit 1
