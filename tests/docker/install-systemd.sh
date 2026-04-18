#!/usr/bin/env bash
#
# Systemd service install verification for the DynamicUser-based Linux
# service unit. Stands up a privileged ubuntu:24.04 container with systemd
# as PID 1, builds numa inside, runs three scenarios that CI does not:
#
#   A. Fresh install — every advertised port is not just bound but
#      functional (DNS resolves on :53, TLS handshake validates against
#      numa's CA on :853/:443, HTTP responds on :80, API on :5380).
#   B. Upgrade from pre-drop layout (root-owned /var/lib/numa) preserves
#      the CA fingerprint — users' browser-installed CA trust survives.
#   C. Install from a 0700 source directory stages the binary under
#      /usr/local/bin/numa and the service starts from there.
#
# First run is slow (~5-10 min): image pull + apt + cold cargo build.
# Subsequent runs reuse cached docker volumes for cargo + target (~30s).
#
# Requirements: docker
# Usage:        ./tests/docker/install-systemd.sh

set -u
set -o pipefail

GREEN="\033[32m"; RED="\033[31m"; RESET="\033[0m"

pass() { printf "  ${GREEN}PASS${RESET}: %s\n" "$*"; }
fail() { printf "  ${RED}FAIL${RESET}: %s\n" "$*"; FAIL=1; }

# ============================================================
# Mode B: running inside the systemd container — run scenarios
# ============================================================
if [ "${NUMA_INSIDE:-}" = "1" ]; then
    set +e  # assertions report pass/fail, don't abort
    FAIL=0
    NUMA=/work/target/release/numa

    reset_state() {
        "$NUMA" uninstall >/dev/null 2>&1 || true
        systemctl reset-failed numa 2>/dev/null || true
        rm -rf /var/lib/numa /var/lib/private/numa /etc/numa /home/builder /usr/local/bin/numa
        systemctl daemon-reload 2>/dev/null || true
    }

    main_pid_user() {
        local pid
        pid=$(systemctl show -p MainPID --value numa)
        [ "$pid" != "0" ] || { echo ""; return; }
        ps -o user= -p "$pid" 2>/dev/null | tr -d ' '
    }

    # MainPID + user briefly stabilize after a fresh restart. Retry so we
    # don't race the moment systemd flips the service to "active" vs when
    # the forked numa process actually owns MainPID.
    assert_nonroot() {
        local pid user comm n=0
        while [ $n -lt 20 ]; do
            pid=$(systemctl show -p MainPID --value numa)
            if [ "$pid" != "0" ]; then
                comm=$(ps -o comm= -p "$pid" 2>/dev/null | tr -d ' ')
                user=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
                if [ "$comm" = "numa" ]; then
                    if [ "$user" = "root" ]; then
                        fail "daemon runs as root (expected transient UID)"
                    else
                        pass "daemon runs as $user (non-root)"
                    fi
                    return
                fi
            fi
            sleep 0.2
            n=$((n + 1))
        done
        fail "numa MainPID did not settle (last: pid=${pid:-?} comm=${comm:-?} user=${user:-?})"
    }

    # Functional DNS check: just "port 53 bound" isn't enough — systemd-resolved
    # listens on 127.0.0.53 and would satisfy a bind test. Retries for ~15s
    # to tolerate cold-start upstream / blocklist warmup.
    assert_dns_works() {
        local n=0
        while [ $n -lt 15 ]; do
            if dig @127.0.0.1 -p 53 example.com +short +timeout=2 +tries=1 2>/dev/null \
                 | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
                pass "DNS resolves on :53 (A record returned)"
                return
            fi
            sleep 1
            n=$((n + 1))
        done
        fail "DNS did not return an A record on :53 within 15s"
    }

    # TLS handshake: cert must validate against numa's CA when connecting
    # to a .numa SNI. Catches port-not-bound, wrong cert, missing CA file.
    assert_tls_handshake() {
        local port=$1 sni=${2:-numa.numa} out
        if out=$(openssl s_client -connect "127.0.0.1:${port}" \
                    -servername "$sni" \
                    -CAfile /var/lib/numa/ca.pem \
                    -verify_return_error </dev/null 2>&1); then
            if echo "$out" | grep -q 'Verify return code: 0 (ok)'; then
                pass "TLS handshake + cert chain verified on :${port}"
            else
                fail "TLS handshake on :${port} did not report 'Verify return code: 0'"
            fi
        else
            fail "openssl s_client failed connecting to :${port}"
        fi
    }

    assert_http_responds() {
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 http://127.0.0.1/ || echo 000)
        if [ "$code" != "000" ]; then
            pass "HTTP responds on :80 (status $code)"
        else
            fail "HTTP :80 connection failed"
        fi
    }

    assert_api_healthy() {
        if curl -sf --max-time 3 http://127.0.0.1:5380/health >/dev/null; then
            pass "API /health OK on :5380"
        else
            fail "API /health failed on :5380"
        fi
    }

    ca_fingerprint() {
        openssl x509 -in /var/lib/numa/ca.pem -noout -fingerprint -sha256 2>/dev/null \
            | sed 's/.*=//'
    }

    wait_active() {
        local n=0
        while [ $n -lt 20 ]; do
            systemctl is-active --quiet numa && return 0
            sleep 0.5
            n=$((n + 1))
        done
        fail "service did not become active within 10s"
        systemctl status numa --no-pager -l 2>&1 | head -20 || true
        return 1
    }

    # ---- Scenario A ----
    printf "\n=== Scenario A: fresh install — every advertised port is functional ===\n"
    reset_state
    "$NUMA" install >/tmp/installA.log 2>&1 || { fail "install failed"; tail -20 /tmp/installA.log; }
    wait_active || true
    assert_nonroot
    assert_dns_works
    assert_tls_handshake 853
    assert_tls_handshake 443
    assert_http_responds
    assert_api_healthy

    # ---- Scenario B ----
    # Pre-drop installs left /var/lib/numa as a plain root-owned tree.
    # Flattening the current DynamicUser layout back into that shape
    # simulates the upgrade path without needing an actual old binary.
    printf "\n=== Scenario B: CA fingerprint survives upgrade from pre-drop layout ===\n"
    fp_before=$(ca_fingerprint)
    if [ -z "$fp_before" ]; then
        fail "could not read initial CA fingerprint (skipping scenario B)"
    else
        echo "  CA fingerprint before: $fp_before"
        "$NUMA" uninstall >/dev/null 2>&1 || true
        tmp=$(mktemp -d)
        cp -a /var/lib/private/numa/. "$tmp"/ 2>/dev/null || true
        rm -rf /var/lib/numa /var/lib/private/numa
        mv "$tmp" /var/lib/numa
        chown -R root:root /var/lib/numa
        chmod 755 /var/lib/numa
        [ -f /var/lib/numa/ca.pem ] || fail "ca.pem missing from seeded legacy tree"

        "$NUMA" install >/tmp/installB.log 2>&1 || { fail "upgrade install failed"; tail -20 /tmp/installB.log; }
        wait_active || true
        assert_nonroot
        fp_after=$(ca_fingerprint)
        if [ -z "$fp_after" ]; then
            fail "could not read CA fingerprint after upgrade"
        elif [ "$fp_before" = "$fp_after" ]; then
            pass "CA fingerprint preserved across upgrade"
        else
            fail "CA fingerprint changed: before=$fp_before after=$fp_after"
        fi
        assert_dns_works
    fi

    # ---- Scenario C ----
    printf "\n=== Scenario C: install from unreachable source stages binary to /usr/local/bin ===\n"
    reset_state
    mkdir -p /home/builder
    chmod 700 /home/builder
    cp "$NUMA" /home/builder/numa
    chmod 755 /home/builder/numa
    /home/builder/numa install >/tmp/installC.log 2>&1 || { fail "install failed"; tail -20 /tmp/installC.log; }
    wait_active || true
    if [ -x /usr/local/bin/numa ]; then
        pass "binary staged to /usr/local/bin/numa"
    else
        fail "/usr/local/bin/numa missing after install from 0700 source"
    fi
    exec_line=$(grep '^ExecStart=' /etc/systemd/system/numa.service 2>/dev/null || echo "ExecStart=<unit missing>")
    if echo "$exec_line" | grep -q '/usr/local/bin/numa'; then
        pass "unit ExecStart points to staged path"
    else
        fail "unit ExecStart wrong: $exec_line"
    fi
    assert_nonroot
    assert_dns_works

    reset_state
    rm -rf /home/builder
    echo
    if [ "$FAIL" -eq 0 ]; then
        printf "${GREEN}── all scenarios passed ──${RESET}\n"
        exit 0
    else
        printf "${RED}── some scenarios failed ──${RESET}\n"
        exit 1
    fi
fi

# ============================================================
# Mode A: host-side bootstrap
# ============================================================
set -e
cd "$(dirname "$0")/../.."

IMAGE=numa-install-systemd:local
CONTAINER="numa-install-systemd-$$"
trap 'docker rm -f "$CONTAINER" >/dev/null 2>&1 || true' EXIT

echo "── building systemd-in-container image (cached after first run) ──"
docker build --quiet -t "$IMAGE" -f - . <<'DOCKERFILE' >/dev/null
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq \
      systemd systemd-sysv systemd-resolved \
      ca-certificates curl build-essential \
      pkg-config libssl-dev cmake make perl \
      dnsutils iproute2 openssl \
    && rm -rf /var/lib/apt/lists/* \
    && for u in dev-hugepages.mount sys-fs-fuse-connections.mount \
                systemd-logind.service getty.target console-getty.service; do \
         systemctl mask $u; \
       done
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
DOCKERFILE

echo "── starting systemd container ──"
docker run -d --name "$CONTAINER" \
    --privileged --cgroupns=host \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp:exec \
    -v "$PWD:/src:ro" \
    -v numa-install-systemd-cargo:/root/.cargo \
    -v numa-install-systemd-work:/work \
    "$IMAGE" >/dev/null

# Wait for systemd to be up
for _ in $(seq 1 30); do
    state=$(docker exec "$CONTAINER" systemctl is-system-running 2>&1 || true)
    case "$state" in running|degraded) break ;; esac
    sleep 0.5
done

echo "── copying source into /work (writable) ──"
docker exec "$CONTAINER" bash -c '
mkdir -p /work
tar -C /src --exclude=./target --exclude=./.git --exclude=./.claude -cf - . | tar -C /work -xf -
'

echo "── rustup + cargo build --release --locked ──"
docker exec "$CONTAINER" bash -c '
set -e
if ! command -v cargo &>/dev/null; then
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --quiet
fi
. "$HOME/.cargo/env"
cd /work
cargo build --release --locked 2>&1 | tail -5
'

echo "── running scenarios ──"
docker exec -e NUMA_INSIDE=1 "$CONTAINER" bash /src/tests/docker/install-systemd.sh
