#!/usr/bin/env bash
# Regression for issue #281: dashboard uptime must track wall-clock so it
# agrees with systemd's "active (running) since N ago" across host suspend.
#
# A container can't actually suspend, but suspend is observably just "the
# real-time clock advanced while the monotonic clock did not". libfaketime
# with DONT_FAKE_MONOTONIC=1 reproduces exactly that: it fakes
# CLOCK_REALTIME (Rust's SystemTime) while passing CLOCK_MONOTONIC (Rust's
# Instant) straight through.
#
#   1. start numa with the fake clock at T0           → uptime ~0
#   2. jump the fake real-time clock to T0 + 10h       → simulates suspend
#   3. read uptime again
#        fixed  (SystemTime): ~36000s — matches a 10h systemd "active since"
#        broken (Instant):    ~0s     — the #281 undercount
#
# PASS iff uptime followed the wall-clock jump. Builds numa inside the image
# so it runs regardless of host OS/arch (the dev host is macOS).
#
# Usage:
#   tests/docker/issue-281-repro.sh
#   JUMP_HOURS=24 tests/docker/issue-281-repro.sh

set -euo pipefail

JUMP_HOURS="${JUMP_HOURS:-10}"
REPO_ROOT="$(git rev-parse --show-toplevel)"
IMAGE="numa-281-repro"
NAME="numa-281-$$"
CTX="$(mktemp -d)"

# Pin build + run to the host arch so the multi-arch base images don't
# resolve build and run stages to different platforms.
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

# ---- Build context: tracked files at HEAD (no target/, no .git) ----
git -C "$REPO_ROOT" archive HEAD | tar -x -C "$CTX"

cat > "$CTX/numa.toml" <<'EOF'
[server]
bind_addr = "127.0.0.1:5353"
api_port = 5381
data_dir = "/tmp/numa"

[upstream]
mode = "forward"
address = "9.9.9.9:53"
EOF

cat > "$CTX/entrypoint.sh" <<'EOF'
#!/bin/sh
set -e
mkdir -p /tmp/numa
LIB="$(find /usr/lib -name 'libfaketime.so.1' | head -1)"
export LD_PRELOAD="$LIB"
export FAKETIME_TIMESTAMP_FILE=/faketime.rc
export FAKETIME_NO_CACHE=1
export DONT_FAKE_MONOTONIC=1
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
    libfaketime curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/debug/numa /usr/local/bin/numa
COPY numa.toml /numa.toml
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && echo "@2030-01-01 00:00:00" > /faketime.rc
ENTRYPOINT ["/entrypoint.sh"]
EOF

# Force-pull bases at the target platform first: `docker run/build` reuses a
# locally-tagged image regardless of --platform, so a stale wrong-arch base
# would otherwise be silently inherited.
for base in rust:1-bookworm debian:bookworm-slim; do
    docker pull $PLAT_ARG -q "$base" >/dev/null
done

echo "${DIM}Building numa image (first run compiles the crate — a few min)...${RESET}"
docker build $PLAT_ARG -q -t "$IMAGE" "$CTX" >/dev/null

echo "${DIM}Starting numa under a frozen-monotonic fake clock...${RESET}"
docker run $PLAT_ARG -d --name "$NAME" "$IMAGE" >/dev/null

uptime_now() {
    docker exec "$NAME" curl -s --max-time 3 http://127.0.0.1:5381/health \
        | grep -o '"uptime_secs":[0-9]*' | cut -d: -f2
}

# Wait for the API to answer.
for _ in $(seq 1 30); do
    U="$(uptime_now || true)"
    [ -n "${U:-}" ] && break
    sleep 0.5
done
[ -n "${U:-}" ] || { echo "${RED}✗${RESET} numa API never came up"; docker logs "$NAME" 2>&1 | tail -20; exit 2; }

UPTIME_BEFORE="$U"
echo "${GREEN}✓${RESET} numa up; uptime before jump = ${UPTIME_BEFORE}s"

# Jump the fake real-time clock forward — monotonic stays frozen (suspend).
docker exec "$NAME" sh -c "echo '@2030-01-01 ${JUMP_HOURS}:00:00' > /faketime.rc"
sleep 1
UPTIME_AFTER="$(uptime_now)"
echo "${DIM}jumped wall-clock +${JUMP_HOURS}h; uptime after = ${UPTIME_AFTER}s${RESET}"

EXPECTED=$(( JUMP_HOURS * 3600 ))
DELTA=$(( UPTIME_AFTER - UPTIME_BEFORE ))

# Allow generous slack for startup/exec latency; the bug yields DELTA ~0.
if [ "$DELTA" -ge $(( EXPECTED - 120 )) ]; then
    echo "${GREEN}✓ PASS${RESET} uptime tracked the +${JUMP_HOURS}h wall-clock jump (Δ=${DELTA}s) — matches systemd"
    exit 0
else
    echo "${RED}✗ FAIL${RESET} uptime did not follow wall-clock (Δ=${DELTA}s, expected ~${EXPECTED}s) — #281 undercount"
    exit 1
fi
