#!/usr/bin/env bash
#
# Arch Linux compatibility smoke test.
#
# Builds numa from source inside an archlinux:latest container, runs it
# in forward mode on port 5354, and verifies a single DNS query returns
# an A record. Validates the "Arch compatible" claim end-to-end before
# release announcements.
#
# Dogfooding: the test numa forwards to the host's running numa via
# host.docker.internal (Docker Desktop's host gateway). This avoids the
# Docker NAT/UDP issues with public resolvers and exercises the realistic
# numa-on-numa shape. Requires the host to be running numa on port 53.
#
# First run is slow (~8-12 min): image pull + pacman + cold cargo build.
# No caching across runs.
#
# Requirements: docker, host running numa on 0.0.0.0:53
# Usage:        ./tests/docker/smoke-arch.sh

set -euo pipefail

cd "$(dirname "$0")/../.."

GREEN="\033[32m"; RED="\033[31m"; RESET="\033[0m"

# Precondition: the test numa-on-arch forwards to the host numa as its
# upstream (dogfood pattern). Fail fast with a clear error if there is
# no working DNS on the host, rather than letting the dig inside the
# container time out with "deadline has elapsed".
if ! dig @127.0.0.1 google.com A +short +time=1 +tries=1 >/dev/null 2>&1; then
    printf "${RED}error:${RESET} host numa is not answering on 127.0.0.1:53\n" >&2
    echo "  This test forwards to the host numa via host.docker.internal." >&2
    echo "  Start numa on the host first (sudo numa install), then rerun." >&2
    exit 1
fi

echo "── building + running numa on archlinux:latest ──"
echo "  (first run is slow: image pull + pacman + cold cargo build, ~8-12 min)"
echo

docker run --rm \
    --platform linux/amd64 \
    --security-opt seccomp=unconfined \
    -v "$PWD:/src:ro" \
    -v numa-arch-cargo:/root/.cargo \
    -v numa-arch-target:/work/target \
    archlinux:latest bash -c '
    set -e

    # pacman 7+ filters syscalls in its own sandbox; disable for Rosetta/qemu
    sed -i "s/^#DisableSandboxSyscalls/DisableSandboxSyscalls/" /etc/pacman.conf

    echo "── pacman: installing build + runtime deps ──"
    pacman -Sy --noconfirm --needed rust gcc pkgconf cmake make perl bind 2>&1 | tail -3
    echo

    # Copy source to a writable workdir, skipping target/ + .git so we
    # do not pull in the host (macOS) build artifacts.
    mkdir -p /work
    tar -C /src --exclude=./target --exclude=./.git -cf - . | tar -C /work -xf -
    cd /work

    echo "── cargo build --release --locked ──"
    cargo build --release --locked 2>&1 | tail -5
    echo

    # Dogfood: forward to the host numa via host.docker.internal.
    # numa parses upstream.address as a literal SocketAddr, so we resolve
    # the hostname to an IPv4 address first (force v4 — getent hosts may
    # return IPv6 first, and IPv6 addresses need bracketed addr:port form).
    HOST_IP=$(getent ahostsv4 host.docker.internal | awk "/STREAM/ {print \$1; exit}")
    if [ -z "$HOST_IP" ]; then
        echo "  ✗ could not resolve host.docker.internal to IPv4 (not on Docker Desktop?)"
        exit 1
    fi
    echo "── starting numa on :5354 (forward to host numa at $HOST_IP:53) ──"
    # Intentionally NOT setting [server] data_dir — we want to exercise the
    # default code path (data_dir() → daemon_data_dir() → /var/lib/numa) so
    # the FHS-path assertion below verifies the live wiring, not just the
    # unit-tested helper.
    cat > /tmp/numa.toml <<EOF
[server]
bind_addr = "127.0.0.1:5354"
api_port = 5381

[upstream]
mode = "forward"
address = "$HOST_IP"
port = 53
EOF

    ./target/release/numa /tmp/numa.toml > /tmp/numa.log 2>&1 &
    NUMA_PID=$!

    # Poll for readiness — numa is ready when it answers a query
    READY=0
    for i in 1 2 3 4 5 6 7 8; do
        sleep 1
        if dig @127.0.0.1 -p 5354 google.com A +short +time=1 +tries=1 2>/dev/null \
            | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"; then
            READY=1
            break
        fi
    done

    if [ "$READY" -ne 1 ]; then
        echo "  ✗ numa did not return an A record after 8s"
        echo "  numa log:"
        cat /tmp/numa.log
        kill $NUMA_PID 2>/dev/null || true
        exit 1
    fi

    echo "── dig @127.0.0.1 -p 5354 google.com A ──"
    ANSWER=$(dig @127.0.0.1 -p 5354 google.com A +short +time=2 +tries=1)
    echo "$ANSWER" | sed "s/^/  /"

    kill $NUMA_PID 2>/dev/null || true

    # FHS path assertion: the default data dir on Linux must be /var/lib/numa
    # (not the legacy /usr/local/var/numa). The CA cert generated at startup
    # is the canonical proof that numa wrote to the right place.
    echo
    echo "── FHS path check ──"
    if [ -f /var/lib/numa/ca.pem ]; then
        echo "  ✓ CA cert at /var/lib/numa/ca.pem (FHS path)"
    else
        echo "  ✗ CA cert NOT at /var/lib/numa/ca.pem"
        echo "  ls /var/lib/numa/:"
        ls -la /var/lib/numa/ 2>&1 | sed "s/^/    /"
        echo "  ls /usr/local/var/numa/:"
        ls -la /usr/local/var/numa/ 2>&1 | sed "s/^/    /"
        exit 1
    fi
    if [ -e /usr/local/var/numa ]; then
        echo "  ✗ legacy path /usr/local/var/numa unexpectedly exists on a fresh container"
        exit 1
    fi
    echo "  ✓ legacy path /usr/local/var/numa absent (fresh install used FHS)"

    echo
    echo "  ✓ numa built, ran, answered a forward query, and used the FHS data dir on Arch"
'

echo
printf "${GREEN}── smoke-arch passed ──${RESET}\n"
