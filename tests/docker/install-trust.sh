#!/usr/bin/env bash
#
# Cross-distro CA trust contract test for issue #35.
#
# Runs the exact shell commands `src/system_dns.rs::trust_ca_linux` would run
# on each Linux trust-store family (Debian, Fedora pki, Arch p11-kit), and
# asserts the certificate ends up in (and is removed from) the system bundle.
#
# This is a contract test, not an integration test: it doesn't drive the Rust
# code (that would need systemd-in-container). It verifies the assumptions in
# `LINUX_TRUST_STORES` against the real distro behavior. If you change that
# table in src/system_dns.rs, update the per-distro cases below to match.
#
# Requirements: docker, openssl (host).
# Usage:        ./tests/docker/install-trust.sh

set -euo pipefail

cd "$(dirname "$0")/../.."

GREEN="\033[32m"; RED="\033[31m"; RESET="\033[0m"

# Self-signed CA fixture, mounted into each container as ca.pem.
# basicConstraints=CA:TRUE is required — without it, Debian's
# update-ca-certificates silently skips the cert during bundle build.
FIXTURE_DIR=$(mktemp -d)
trap 'rm -rf "$FIXTURE_DIR"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$FIXTURE_DIR/ca.key" \
    -out    "$FIXTURE_DIR/ca.pem" \
    -subj   "/CN=Numa Local CA Test $(date +%s)" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

# Distro bundles store certs differently — Debian writes raw PEM only,
# Fedora prepends "# CN" comment headers, Arch via extract-compat is
# raw PEM. To detect cert presence uniformly we grep for a deterministic
# substring of the base64 body (first base64 line is unique per cert).
CERT_TAG=$(sed -n '2p' "$FIXTURE_DIR/ca.pem")

PASSED=0; FAILED=0

run_case() {
    local distro="$1"; shift
    local image="$1"; shift
    local platform="$1"; shift
    local script="$1"

    printf "── %s (%s) ──\n" "$distro" "$image"
    if docker run --rm \
        --platform "$platform" \
        --security-opt seccomp=unconfined \
        -e CERT_TAG="$CERT_TAG" \
        -e DEBIAN_FRONTEND=noninteractive \
        -v "$FIXTURE_DIR/ca.pem:/fixture/ca.pem:ro" \
        "$image" bash -c "$script"; then
        printf "${GREEN}✓${RESET} %s\n\n" "$distro"
        PASSED=$((PASSED + 1))
    else
        printf "${RED}✗${RESET} %s\n\n" "$distro"
        FAILED=$((FAILED + 1))
    fi
}

# Debian / Ubuntu / Mint — anchor: /usr/local/share/ca-certificates/*.crt
run_case "debian" "debian:stable" "linux/amd64" '
    set -e
    apt-get update -qq
    apt-get install -qq -y ca-certificates >/dev/null
    install -m 0644 /fixture/ca.pem /usr/local/share/ca-certificates/numa-local-ca.crt
    update-ca-certificates >/dev/null 2>&1
    grep -q "$CERT_TAG" /etc/ssl/certs/ca-certificates.crt
    echo "  install: cert present in bundle"
    rm /usr/local/share/ca-certificates/numa-local-ca.crt
    update-ca-certificates --fresh >/dev/null 2>&1
    if grep -q "$CERT_TAG" /etc/ssl/certs/ca-certificates.crt; then
        echo "  uninstall: cert STILL present (regression)" >&2
        exit 1
    fi
    echo "  uninstall: cert removed from bundle"
'

# Fedora / RHEL / CentOS / SUSE — anchor: /etc/pki/ca-trust/source/anchors/*.pem
run_case "fedora" "fedora:latest" "linux/amd64" '
    set -e
    dnf install -q -y ca-certificates >/dev/null
    install -m 0644 /fixture/ca.pem /etc/pki/ca-trust/source/anchors/numa-local-ca.pem
    update-ca-trust extract
    grep -q "$CERT_TAG" /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
    echo "  install: cert present in bundle"
    rm /etc/pki/ca-trust/source/anchors/numa-local-ca.pem
    update-ca-trust extract
    if grep -q "$CERT_TAG" /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem; then
        echo "  uninstall: cert STILL present (regression)" >&2
        exit 1
    fi
    echo "  uninstall: cert removed from bundle"
'

# Arch / Manjaro — anchor: /etc/ca-certificates/trust-source/anchors/*.pem
# archlinux:latest is x86_64-only; --platform forces emulation on Apple Silicon.
run_case "arch" "archlinux:latest" "linux/amd64" '
    set -e
    # pacman 7+ filters syscalls in its own sandbox; disable for Rosetta/qemu emulation.
    sed -i "s/^#DisableSandboxSyscalls/DisableSandboxSyscalls/" /etc/pacman.conf
    pacman -Sy --noconfirm --needed ca-certificates p11-kit >/dev/null 2>&1
    install -m 0644 /fixture/ca.pem /etc/ca-certificates/trust-source/anchors/numa-local-ca.pem
    trust extract-compat
    grep -q "$CERT_TAG" /etc/ssl/certs/ca-certificates.crt
    echo "  install: cert present in bundle"
    rm /etc/ca-certificates/trust-source/anchors/numa-local-ca.pem
    trust extract-compat
    if grep -q "$CERT_TAG" /etc/ssl/certs/ca-certificates.crt; then
        echo "  uninstall: cert STILL present (regression)" >&2
        exit 1
    fi
    echo "  uninstall: cert removed from bundle"
'

printf "── summary ──\n"
printf "  ${GREEN}passed${RESET}: %d\n" "$PASSED"
printf "  ${RED}failed${RESET}: %d\n" "$FAILED"
[ "$FAILED" -eq 0 ]
