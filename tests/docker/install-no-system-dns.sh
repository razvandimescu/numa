#!/usr/bin/env bash
#
# Cross-distro verification of `numa install --no-system-dns`.
#
# Asserts on each distro: install registers + activates the systemd unit
# but leaves /etc/resolv.conf and /etc/systemd/resolved.conf.d/numa.conf
# untouched, and uninstall handles the missing backup file as a no-op
# (returns 0, does not error with "no backup found").
#
# Each distro runs in its own privileged systemd-as-PID-1 container,
# builds numa from /src, then runs the scenario. First run is slow per
# distro (~3-6 min for image pull + apt/dnf/pacman + cold cargo build);
# subsequent runs reuse cached cargo + target volumes (~30s per distro).
#
# Requirements: docker
# Usage:        ./tests/docker/install-no-system-dns.sh
#               DISTROS=ubuntu:24.04 ./tests/docker/install-no-system-dns.sh   # subset

set -u
set -o pipefail

GREEN="\033[32m"; RED="\033[31m"; DIM="\033[90m"; RESET="\033[0m"

# archlinux:latest is x86_64-only and fails to build under Rosetta/qemu
# emulation on Apple Silicon (pacman 7 sandbox + emulation interaction).
# Opt in explicitly when running on amd64 hosts: DISTROS="... archlinux:latest"
DISTROS_DEFAULT=(
    "ubuntu:24.04"
    "debian:bookworm"
    "fedora:latest"
)
read -ra DISTROS <<<"${DISTROS:-${DISTROS_DEFAULT[*]}}"

# ============================================================
# Mode B: running inside a distro container
# ============================================================
if [ "${NUMA_INSIDE:-}" = "1" ]; then
    set +e
    NUMA=/work/target/release/numa
    FAIL=0

    pass() { printf "  ${GREEN}PASS${RESET}: %s\n" "$*"; }
    fail() { printf "  ${RED}FAIL${RESET}: %s\n" "$*"; FAIL=1; }

    wait_active() {
        local n=0
        while [ $n -lt 20 ]; do
            systemctl is-active --quiet numa && return 0
            sleep 0.5
            n=$((n + 1))
        done
        return 1
    }

    # Capture pre-install state of system DNS knobs we expect to leave alone.
    snapshot_before() {
        cp -a /etc/resolv.conf /tmp/resolv.before 2>/dev/null || touch /tmp/resolv.before
        ls -la /etc/systemd/resolved.conf.d/ 2>/dev/null > /tmp/resolved-d.before || true
    }

    assert_resolv_unchanged() {
        if diff -q /tmp/resolv.before /etc/resolv.conf >/dev/null 2>&1; then
            pass "/etc/resolv.conf unchanged"
        else
            fail "/etc/resolv.conf was modified"
            diff /tmp/resolv.before /etc/resolv.conf | head -10 || true
        fi
    }

    assert_no_resolved_dropin() {
        if [ ! -f /etc/systemd/resolved.conf.d/numa.conf ]; then
            pass "no /etc/systemd/resolved.conf.d/numa.conf written"
        else
            fail "drop-in /etc/systemd/resolved.conf.d/numa.conf exists"
        fi
    }

    assert_unit_registered() {
        if [ -f /etc/systemd/system/numa.service ]; then
            pass "/etc/systemd/system/numa.service installed"
        else
            fail "unit file missing"
        fi
    }

    printf "\n=== Scenario: install --no-system-dns leaves system DNS alone ===\n"
    snapshot_before
    "$NUMA" install --no-system-dns >/tmp/install.log 2>&1
    rc=$?
    if [ $rc -ne 0 ]; then
        fail "install --no-system-dns exited $rc"
        tail -20 /tmp/install.log
    else
        pass "install --no-system-dns exited 0"
    fi
    wait_active && pass "service is active" || fail "service did not become active"
    assert_unit_registered
    assert_resolv_unchanged
    assert_no_resolved_dropin
    if grep -q "no-system-dns" /tmp/install.log; then
        pass "install output mentions --no-system-dns notice"
    else
        fail "install output missing --no-system-dns notice"
    fi

    printf "\n=== Scenario: uninstall is a no-op when no backup exists ===\n"
    "$NUMA" uninstall >/tmp/uninstall.log 2>&1
    rc=$?
    if [ $rc -eq 0 ]; then
        pass "uninstall exited 0 (graceful no-op)"
    else
        fail "uninstall exited $rc (regression)"
        tail -10 /tmp/uninstall.log
    fi
    if systemctl is-active --quiet numa; then
        fail "service still active after uninstall"
    else
        pass "service stopped"
    fi

    if [ "$FAIL" -eq 0 ]; then
        printf "\n${GREEN}── all checks passed ──${RESET}\n"
        exit 0
    else
        printf "\n${RED}── checks failed ──${RESET}\n"
        exit 1
    fi
fi

# ============================================================
# Mode A: host-side bootstrap, one container per distro
# ============================================================
set -e
cd "$(dirname "$0")/../.."
SRC=$PWD

# Build the per-distro systemd image. Tag is `numa-no-system-dns-<distro>:local`.
# Sets the global IMAGE_TAG so callers can read it without re-deriving.
build_image() {
    local distro="$1"
    IMAGE_TAG="numa-no-system-dns-${distro//[:.\/]/-}:local"

    local dockerfile
    case "$distro" in
        ubuntu:*|debian:*)
            dockerfile=$(cat <<DOCKERFILE
FROM $distro
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq \
      systemd systemd-sysv ca-certificates curl build-essential \
      pkg-config libssl-dev cmake make perl iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && for u in dev-hugepages.mount sys-fs-fuse-connections.mount \
                systemd-logind.service getty.target console-getty.service; do \
         systemctl mask \$u; \
       done
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
DOCKERFILE
)
            ;;
        archlinux:*)
            # pacman 7+ sandboxes syscalls; disable for cross-arch emulation.
            dockerfile=$(cat <<DOCKERFILE
FROM $distro
RUN sed -i 's/^#DisableSandboxSyscalls/DisableSandboxSyscalls/' /etc/pacman.conf \
    && pacman -Sy --noconfirm --needed \
         systemd ca-certificates curl base-devel \
         pkgconf openssl cmake make perl iproute2 \
    && for u in dev-hugepages.mount sys-fs-fuse-connections.mount \
                systemd-logind.service getty.target console-getty.service; do \
         systemctl mask \$u; \
       done
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
DOCKERFILE
)
            ;;
        fedora:*)
            dockerfile=$(cat <<DOCKERFILE
FROM $distro
RUN dnf install -q -y \
      systemd ca-certificates curl gcc gcc-c++ \
      pkgconfig openssl-devel cmake make perl-core iproute \
    && dnf clean all \
    && for u in dev-hugepages.mount sys-fs-fuse-connections.mount \
                systemd-logind.service getty.target console-getty.service; do \
         systemctl mask \$u; \
       done
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
DOCKERFILE
)
            ;;
        *)
            echo "unsupported distro: $distro" >&2
            return 1
            ;;
    esac
    docker build "${@:2}" -t "$IMAGE_TAG" -f - . <<<"$dockerfile" 2>&1 | tail -5
    docker image inspect "$IMAGE_TAG" >/dev/null 2>&1
}

run_distro() {
    local distro="$1"
    local container="numa-no-system-dns-${distro//[:.\/]/-}-$$"
    local cargo_vol="numa-no-system-dns-cargo-${distro//[:.\/]/-}"
    local work_vol="numa-no-system-dns-work-${distro//[:.\/]/-}"
    local rc

    # archlinux only publishes x86_64 — force amd64 for both build and run.
    # Other distros use the host's native arch (arm64 on Apple Silicon),
    # which avoids slow QEMU emulation for the cargo build.
    local platform=()
    case "$distro" in
        archlinux:*) platform=(--platform linux/amd64) ;;
    esac

    printf "\n${DIM}── %s: building image ──${RESET}\n" "$distro"
    if ! build_image "$distro" "${platform[@]+"${platform[@]}"}"; then
        echo "image build failed for $distro" >&2
        return 1
    fi

    docker rm -f "$container" >/dev/null 2>&1 || true
    printf "${DIM}── %s: starting systemd container (%s) ──${RESET}\n" "$distro" "$IMAGE_TAG"
    docker run -d --name "$container" \
        "${platform[@]+"${platform[@]}"}" \
        --privileged --cgroupns=host \
        --tmpfs /run --tmpfs /run/lock --tmpfs /tmp:exec \
        -v "$SRC:/src:ro" \
        -v "$cargo_vol:/root/.cargo" \
        -v "$work_vol:/work" \
        "$IMAGE_TAG" >/dev/null

    # Wait for systemd to be up
    for _ in $(seq 1 30); do
        state=$(docker exec "$container" systemctl is-system-running 2>&1 || true)
        case "$state" in running|degraded) break ;; esac
        sleep 0.5
    done

    printf "${DIM}── %s: copying source + cargo build --release (cached) ──${RESET}\n" "$distro"
    docker exec "$container" bash -c '
set -e
mkdir -p /work
tar -C /src --exclude=./target --exclude=./.git --exclude=./.claude -cf - . | tar -C /work -xf -
if ! command -v cargo &>/dev/null; then
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --quiet
fi
. "$HOME/.cargo/env"
cd /work
cargo build --release --locked 2>&1 | tail -3
'

    printf "${DIM}── %s: running scenario ──${RESET}\n" "$distro"
    docker exec -e NUMA_INSIDE=1 "$container" bash /src/tests/docker/install-no-system-dns.sh
    rc=$?

    docker rm -f "$container" >/dev/null 2>&1 || true
    return $rc
}

declare -a PASSED=()
declare -a FAILED=()
set +e
for distro in "${DISTROS[@]}"; do
    printf "\n${GREEN}══════ %s ══════${RESET}\n" "$distro"
    if run_distro "$distro"; then
        PASSED+=("$distro")
    else
        FAILED+=("$distro")
    fi
done

printf "\n══════ summary ══════\n"
for d in "${PASSED[@]+"${PASSED[@]}"}"; do printf "  ${GREEN}✓${RESET} %s\n" "$d"; done
for d in "${FAILED[@]+"${FAILED[@]}"}"; do printf "  ${RED}✗${RESET} %s\n" "$d"; done
[ ${#FAILED[@]} -eq 0 ]
