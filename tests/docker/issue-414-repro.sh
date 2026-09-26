#!/usr/bin/env bash
# Regression for issue #414: names under a resolv.conf search domain must reach
# the system resolver, not a hardcoded cloud address.
#
# On Linux, discover_linux() turns every `search`/`domain` entry into a
# forwarding rule. Without systemd-resolved the rule used to point at
# 169.254.169.253 (the AWS VPC resolver), which only answers inside a VPC, so
# off AWS everything under the search domain SERVFAILed. CI never saw it: the
# GitHub runners run systemd-resolved, so resolvectl returned a working server.
#
# The slim image has no resolvectl, which is exactly the reporter's setup. One
# container runs two numas:
#
#   zone numa   <container-ip>:53   serves host.example.test from a local zone
#   numa        127.0.0.1:5353      auto-detected upstream, no zones
#
# resolv.conf gets `search example.test` + `nameserver <container-ip>`, so the
# zone numa stands in for the network's resolver. The container IP is used
# because loopback nameservers are filtered out of detection.
#
#   PASS → host.example.test resolves through numa
#   FAIL → SERVFAIL / no answer (the #414 rule to 169.254.169.253)
#
# Usage:
#   tests/docker/issue-414-repro.sh

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
IMAGE="numa-414-repro"
NAME="numa-414-$$"
CTX="$(mktemp -d)"
WANT="192.0.2.14"

case "$(uname -m)" in
    arm64|aarch64) PLATFORM="linux/arm64" ;;
    x86_64|amd64)  PLATFORM="linux/amd64" ;;
    *)             PLATFORM="" ;;
esac
PLAT_ARG=${PLATFORM:+--platform=$PLATFORM}

GREEN="\033[32m"; RED="\033[31m"; DIM="\033[90m"; RESET="\033[0m"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    rm -rf "$CTX"
}
trap cleanup EXIT

TREE="$(git -C "$REPO_ROOT" stash create)"
git -C "$REPO_ROOT" archive "${TREE:-HEAD}" | tar -x -C "$CTX"

cat > "$CTX/zone.toml.in" <<EOF
[server]
bind_addr = "@IP@:53"
api_port = 5382
data_dir = "/tmp/numa-zone"

[blocking]
enabled = false

[proxy]
enabled = false

[[zones]]
domain = "host.example.test"
record_type = "A"
value = "$WANT"
ttl = 60
EOF

# `address` is deliberately absent so the upstream and the search-domain rules
# both come from resolv.conf, as on the reporter's box.
cat > "$CTX/numa.toml" <<'EOF'
[server]
bind_addr = "127.0.0.1:5353"
api_port = 5381
data_dir = "/tmp/numa"

[upstream]
mode = "forward"

[blocking]
enabled = false

[proxy]
enabled = false
EOF

cat > "$CTX/entrypoint.sh" <<'EOF'
#!/bin/sh
set -e
IP="$(hostname -i | awk '{print $1}')"
mkdir -p /tmp/numa /tmp/numa-zone
sed "s/@IP@/$IP/" /zone.toml.in > /zone.toml
printf 'search example.test\nnameserver %s\n' "$IP" > /etc/resolv.conf
numa /zone.toml > /tmp/zone.log 2>&1 &
sleep 1
exec numa /numa.toml
EOF

cat > "$CTX/Dockerfile" <<'EOF'
FROM rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake clang libclang-dev perl && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --bin numa

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/debug/numa /usr/local/bin/numa
COPY numa.toml zone.toml.in entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
EOF

for base in rust:1-bookworm debian:bookworm-slim; do
    docker pull $PLAT_ARG -q "$base" >/dev/null
done

echo -e "${DIM}Building numa image (first run compiles the crate — a few min)...${RESET}"
docker build $PLAT_ARG -q -t "$IMAGE" "$CTX" >/dev/null

echo -e "${DIM}Starting zone numa + numa with search domain example.test...${RESET}"
docker run $PLAT_ARG -d --name "$NAME" "$IMAGE" >/dev/null

query() {
    docker exec "$NAME" dig "$@" A +short +timeout=3 +tries=1 2>/dev/null | grep -E "^[0-9.]+$" || true
}

# Precondition: the zone numa answers directly, otherwise the run proves nothing.
IP="$(docker exec "$NAME" hostname -i | awk '{print $1}')"
for _ in $(seq 1 40); do
    DIRECT="$(query @"$IP" host.example.test)"
    [ "$DIRECT" = "$WANT" ] && break
    sleep 0.5
done
[ "${DIRECT:-}" = "$WANT" ] || {
    echo -e "${RED}✗${RESET} zone numa never answered on $IP:53 — repro invalid"
    docker exec "$NAME" cat /tmp/zone.log 2>/dev/null | tail -20
    exit 2
}
echo -e "${GREEN}✓${RESET} zone numa answers host.example.test on $IP:53 — precondition met"

for _ in $(seq 1 40); do
    docker exec "$NAME" curl -sf --max-time 1 http://127.0.0.1:5381/health >/dev/null 2>&1 && break
    sleep 0.5
done
docker exec "$NAME" curl -sf --max-time 1 http://127.0.0.1:5381/health >/dev/null 2>&1 || {
    echo -e "${RED}✗${RESET} numa API never came up — repro invalid"
    docker logs "$NAME" 2>&1 | tail -20
    exit 2
}

GOT="$(query @127.0.0.1 -p 5353 host.example.test)"
echo -e "${DIM}numa answered: ${GOT:-<nothing>}${RESET}"

if [ "$GOT" = "$WANT" ]; then
    echo -e "${GREEN}✓ PASS${RESET} search domain resolved through the system resolver"
    exit 0
fi
echo -e "${RED}✗ FAIL${RESET} search domain did not resolve — #414"
docker logs "$NAME" 2>&1 | grep -E 'forwarding \.|upstream' || true
exit 1
