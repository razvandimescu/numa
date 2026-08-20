#!/usr/bin/env bash
# Regression for issue #169: the 30s auto-detect rescan must never demote an
# encrypted upstream to plain UDP:53.
#
# serve.rs keeps two fallbacks for the same "can't detect system DNS" state:
#
#   const QUAD9_IP     = "9.9.9.9"                    → used by the rescan
#   const DOH_FALLBACK = "https://9.9.9.9/dns-query"  → used at startup
#
# So a box where detection fails starts on DoH and, 30s later, gets silently
# moved to plain UDP against the same IP. Where outbound UDP:53 is blocked
# (corporate, ISP-restricted, hostile Wi-Fi) every query then SERVFAILs for the
# rest of the process lifetime.
#
# Reproducing needs detection to fail, which is what `nameserver 127.0.0.1`
# gives us — is_loopback_or_stub() filters it, resolvectl is absent from the
# slim image, and detect_dhcp_dns() is a no-op off macOS. That is also exactly
# what a real box looks like after `numa install` makes numa the system
# resolver. Note Docker's own 127.0.0.11 is NOT filtered, so the entrypoint has
# to overwrite resolv.conf or detection succeeds and nothing reproduces.
#
# The demotion is the bug; the SERVFAIL is only its consequence on a hostile
# network, so this asserts the transport rather than blocking UDP.
#
#   PASS → upstream is still DoH after the rescan window
#   FAIL → upstream became 9.9.9.9:53 (the #169 demotion)
#
# Usage:
#   tests/docker/issue-169-repro.sh
#   WINDOW=70 tests/docker/issue-169-repro.sh   # wait longer for the rescan

set -euo pipefail

WINDOW="${WINDOW:-45}"
REPO_ROOT="$(git rev-parse --show-toplevel)"
IMAGE="numa-169-repro"
NAME="numa-169-$$"
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

# ---- Build context: tracked files (no target/, no .git) ----
# `stash create` snapshots uncommitted edits to a throwaway commit without
# touching the worktree or the stash list, so a fix can be verified before it's
# committed. Empty when the tree is clean, hence the HEAD fallback.
TREE="$(git -C "$REPO_ROOT" stash create)"
git -C "$REPO_ROOT" archive "${TREE:-HEAD}" | tar -x -C "$CTX"

# `address` is deliberately absent: upstream_auto is address.is_empty(), and
# only the auto path runs the rescan.
cat > "$CTX/numa.toml" <<'EOF'
[server]
bind_addr = "127.0.0.1:5353"
api_port = 5381
data_dir = "/tmp/numa"

[upstream]
mode = "forward"
EOF

cat > "$CTX/entrypoint.sh" <<'EOF'
#!/bin/sh
set -e
mkdir -p /tmp/numa
# Bind-mounted by Docker, but writable — overwrite the contents in place.
echo "nameserver 127.0.0.1" > /etc/resolv.conf
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
    curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/debug/numa /usr/local/bin/numa
COPY numa.toml /numa.toml
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
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

echo "${DIM}Starting numa with undetectable system DNS...${RESET}"
docker run $PLAT_ARG -d --name "$NAME" "$IMAGE" >/dev/null

upstream_now() {
    docker exec "$NAME" curl -s --max-time 3 http://127.0.0.1:5381/stats \
        | grep -o '"upstream": *"[^"]*"' | cut -d'"' -f4
}

for _ in $(seq 1 40); do
    U="$(upstream_now || true)"
    [ -n "${U:-}" ] && break
    sleep 0.5
done
[ -n "${U:-}" ] || { echo "${RED}✗${RESET} numa API never came up"; docker logs "$NAME" 2>&1 | tail -20; exit 2; }

BEFORE="$U"
echo "${DIM}startup upstream = ${BEFORE}${RESET}"

# Guard the precondition: if detection did NOT fail, startup picked a plain
# upstream and there is no demotion to observe — the run proves nothing.
case "$BEFORE" in
    https://*) echo "${GREEN}✓${RESET} startup fell back to DoH — precondition met" ;;
    *) echo "${RED}✗${RESET} expected a DoH startup upstream, got '${BEFORE}' — system DNS was detected, repro invalid"
       docker logs "$NAME" 2>&1 | tail -20; exit 2 ;;
esac

echo "${DIM}waiting ${WINDOW}s for the 30s rescan...${RESET}"
sleep "$WINDOW"
# `|| true`: a dead container makes grep exit 1, which under `set -e` would
# abort here and be indistinguishable from the #169 demotion below.
AFTER="$(upstream_now || true)"

echo "${DIM}upstream after rescan = ${AFTER:-<unreachable>}${RESET}"

case "${AFTER:-}" in
    https://*)
        echo "${GREEN}✓ PASS${RESET} encrypted upstream survived the rescan (${AFTER})"
        exit 0 ;;
    "")
        echo "${RED}✗${RESET} numa API stopped answering — result inconclusive"
        docker logs "$NAME" 2>&1 | tail -20
        exit 2 ;;
    *)
        echo "${RED}✗ FAIL${RESET} rescan demoted DoH → '${AFTER}' — #169"
        docker logs "$NAME" 2>&1 | grep -E 'falling back|upstream changed' || true
        exit 1 ;;
esac
